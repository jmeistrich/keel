import { test, expect, expectTypeOf, beforeEach } from "vitest";
import { actions, models, resetDatabase } from "@teamkeel/testing";

beforeEach(resetDatabase);

test("create identity", async () => {
  const { identityCreated } = await actions.authenticate({
    createIfNotExists: true,
    emailPassword: {
      email: "user@keel.xyz",
      password: "1234",
    },
  });

  expect(identityCreated).toEqual(true);
});

test("authenticate - invalid email - respond with invalid email address error", async () => {
  await expect(
    actions.authenticate({
      createIfNotExists: true,
      emailPassword: {
        email: "user",
        password: "1234",
      },
    }),
  ).rejects.toEqual({
    code: "ERR_INVALID_INPUT",
    message: "invalid email address",
  });
});

test("authenticate - empty password - respond with password cannot be empty error", async () => {
  await expect(
    actions.authenticate({
      createIfNotExists: true,
      emailPassword: {
        email: "user@keel.xyz",
        password: "",
      },
    }),
  ).rejects.toEqual({
    code: "ERR_INVALID_INPUT",
    message: "password cannot be empty",
  });
});

test("authenticate - new identity and createIfNotExists false - respond with failed to authenticate error", async () => {
  await expect(
    actions.authenticate({
      createIfNotExists: false,
      emailPassword: {
        email: "user@keel.xyz",
        password: "1234",
      },
    }),
  ).rejects.toEqual({
    code: "ERR_INVALID_INPUT",
    message: "failed to authenticate",
  });
});

test("authenticate - existing identity and createIfNotExists false - authenticated", async () => {
  const { identityCreated: created1 } = await actions.authenticate({
    createIfNotExists: true,
    emailPassword: {
      email: "user@keel.xyz",
      password: "1234",
    },
  });

  const { identityCreated: created2 } = await actions.authenticate({
    createIfNotExists: false,
    emailPassword: {
      email: "user@keel.xyz",
      password: "1234",
    },
  });

  const count = (await models.identity.findMany()).length;

  expect(count).toEqual(1);
  expect(created1).toEqual(true);
  expect(created2).toEqual(false);
});

test("authenticate - new identity - new identity created", async () => {
  const authResponse = await actions.authenticate({
    createIfNotExists: true,
    emailPassword: {
      email: "user@keel.xyz",
      password: "1234",
    },
  });
  expect(authResponse.token).toBeTruthy();
  expect(authResponse.identityCreated).toEqual(true);
});

test("authenticate - existing identity - authenticated", async () => {
  const { identityCreated: created1 } = await actions.authenticate({
    createIfNotExists: true,
    emailPassword: {
      email: "user@keel.xyz",
      password: "1234",
    },
  });

  const { identityCreated: created2 } = await actions.authenticate({
    createIfNotExists: true,
    emailPassword: {
      email: "user@keel.xyz",
      password: "1234",
    },
  });

  expect(created1).toEqual(true);
  expect(created2).toEqual(false);
});

test("authenticate - incorrect credentials with existing identity - not authenticated", async () => {
  const { identityCreated: created1 } = await actions.authenticate({
    createIfNotExists: true,
    emailPassword: {
      email: "user@keel.xyz",
      password: "1234",
    },
  });

  expect(created1).toEqual(true);

  await expect(
    actions.authenticate({
      createIfNotExists: true,
      emailPassword: {
        email: "user@keel.xyz",
        password: "zzzz",
      },
    }),
  ).rejects.toEqual({
    code: "ERR_INVALID_INPUT",
    message: "failed to authenticate",
  });
});

test("identity context permission - correct identity - permission satisfied", async () => {
  const authResponse = await actions.authenticate({
    createIfNotExists: true,
    emailPassword: {
      email: "user@keel.xyz",
      password: "1234",
    },
  });

  const authedActions = actions.withAuthToken(authResponse.token);

  const post = await authedActions.createPostWithIdentity({ title: "temp" });

  await expect(
    authedActions.getPostRequiresIdentity({ id: post.id }),
  ).resolves.toEqual(post);
});

test("identity context permission - incorrect identity - permission not satisfied", async () => {
  const { token: token1 } = await actions.authenticate({
    createIfNotExists: true,
    emailPassword: {
      email: "user1@keel.xyz",
      password: "1234",
    },
  });

  const { token: token2 } = await actions.authenticate({
    createIfNotExists: true,
    emailPassword: {
      email: "user2@keel.xyz",
      password: "1234",
    },
  });

  const post = await actions
    .withAuthToken(token1)
    .createPostWithIdentity({ title: "temp" });

  await expect(
    actions.withAuthToken(token2).getPostRequiresIdentity({ id: post.id }),
  ).toHaveAuthorizationError();
});

test("isAuthenticated context permission - authenticated - permission satisfied", async () => {
  const { token } = await actions.authenticate({
    createIfNotExists: true,
    emailPassword: {
      email: "user@keel.xyz",
      password: "1234",
    },
  });

  const post = await actions
    .withAuthToken(token)
    .createPostWithIdentity({ title: "temp" });

  await expect(
    actions.withAuthToken(token).getPostRequiresAuthentication({ id: post.id }),
  ).resolves.toEqual(post);
});

test("isAuthenticated context permission - not authenticated - permission not satisfied", async () => {
  const { token } = await actions.authenticate({
    createIfNotExists: true,
    emailPassword: {
      email: "user@keel.xyz",
      password: "1234",
    },
  });

  const post = await actions
    .withAuthToken(token)
    .createPostWithIdentity({ title: "temp" });

  await expect(
    actions.getPostRequiresAuthentication({ id: post.id }),
  ).toHaveAuthorizationError();
});

test("not isAuthenticated context permission - authenticated - permission satisfied", async () => {
  const { token } = await actions.authenticate({
    createIfNotExists: true,
    emailPassword: {
      email: "user@keel.xyz",
      password: "1234",
    },
  });

  const post = await actions
    .withAuthToken(token)
    .createPostWithIdentity({ title: "temp" });

  await expect(
    actions
      .withAuthToken(token)
      .getPostRequiresNoAuthentication({ id: post.id }),
  ).toHaveAuthorizationError();
});

test("not isAuthenticated context permission - not authenticated - permission satisfied", async () => {
  const { token } = await actions.authenticate({
    createIfNotExists: true,
    emailPassword: {
      email: "user@keel.xyz",
      password: "1234",
    },
  });

  const post = await actions
    .withAuthToken(token)
    .createPostWithIdentity({ title: "temp" });

  await expect(
    actions.getPostRequiresNoAuthentication({ id: post.id }),
  ).resolves.toEqual(post);
});

test("isAuthenticated context set - authenticated - is set to true", async () => {
  const { token } = await actions.authenticate({
    createIfNotExists: true,
    emailPassword: {
      email: "user@keel.xyz",
      password: "1234",
    },
  });

  const post = await actions
    .withAuthToken(token)
    .createPostSetIsAuthenticated({ title: "temp" });

  expect(post.isAuthenticated).toEqual(true);
});

test("isAuthenticated context set - not authenticated - is set to false", async () => {
  const post = await actions.createPostSetIsAuthenticated({
    title: "temp",
  });

  expect(post.isAuthenticated).toEqual(false);
});

// todo:  permission test against null.  Requires this fix:  https://linear.app/keel/issue/DEV-195/permissions-support-null-operand-with-identity-type

// todo:  permission test against another identity field.  Requires this fix: https://linear.app/keel/issue/DEV-196/permissions-support-identity-type-operand-with-identity-comparison

test("related model identity context permission - correct identity - permission satisfied", async () => {
  const { token } = await actions.authenticate({
    createIfNotExists: true,
    emailPassword: {
      email: "user1@keel.xyz",
      password: "1234",
    },
  });

  const post = await actions
    .withAuthToken(token)
    .createPostWithIdentity({ title: "temp" });

  const child = await actions
    .withAuthToken(token)
    .createChild({ post: { id: post.id } });

  const childPosts = await models.childPost.findMany({
    where: { postId: post.id },
  });

  expect(child.postId).toEqual(post.id);
  expect(childPosts.length).toEqual(1);
  expect(childPosts[0].id).toEqual(child.id);
});

test("related model identity context permission - incorrect identity - permission not satisfied", async () => {
  const { token: token1 } = await actions.authenticate({
    createIfNotExists: true,
    emailPassword: {
      email: "user1@keel.xyz",
      password: "1234",
    },
  });

  const { token: token2 } = await actions.authenticate({
    createIfNotExists: true,
    emailPassword: {
      email: "user2@keel.xyz",
      password: "1234",
    },
  });

  const post = await actions
    .withAuthToken(token1)
    .createPostWithIdentity({ title: "temp" });

  await expect(
    actions.withAuthToken(token2).createChild({ post: { id: post.id } }),
  ).toHaveAuthorizationError();

  const childPosts = await models.childPost.findMany({
    where: { postId: post.id },
  });
  expect(childPosts.length).toEqual(0);
});

test("request reset password - invalid email - respond with invalid email address error", async () => {
  await expect(
    actions.requestPasswordReset({
      email: "user",
      redirectUrl: "https://mydomain.com",
    }),
  ).rejects.toEqual({
    code: "ERR_INVALID_INPUT",
    message: "invalid email address",
  });
});

test("request reset password - invalid redirectUrl - respond with invalid redirectUrl error", async () => {
  await expect(
    actions.requestPasswordReset({
      email: "user@keel.xyz",
      redirectUrl: "mydomain",
    }),
  ).rejects.toEqual({
    code: "ERR_INVALID_INPUT",
    message: "invalid redirect URL",
  });
});

test("request reset password - unknown email - successful request", async () => {
  await models.identity.create({
    email: "user@keel.xyz",
    password: "123",
  });

  await expect(
    actions.requestPasswordReset({
      email: "another-user@keel.xyz",
      redirectUrl: "https://mydomain.com",
    }),
  ).not.toHaveError({});
});

// This test will break if we use a private key in the test runtime.
test("reset password - invalid token - token has expired error", async () => {
  const identity = await models.identity.create({
    id: "2OrbbxUb8syZzlDz0v5ofunO1vi",
    email: "user@keel.xyz",
    password: "123",
  });

  await expect(
    actions.resetPassword({
      token: "invalid",
      password: "abc",
    }),
  ).rejects.toEqual({
    code: "ERR_INVALID_INPUT",
    message: "token has expired",
  });
});

// This test will break if we use a private key in the test runtime.
test("reset password - missing aud claim - cannot be parsed error", async () => {
  const identity = await models.identity.create({
    id: "2OrbbxUb8syZzlDz0v5ofunO1vi",
    email: "user@keel.xyz",
    password: "123",
  });

  // {
  //   "typ": "JWT",
  //   "alg": "none"
  // }
  // {
  //   "sub": "2OrbbxUb8syZzlDz0v5ofunO1vi",
  //   "iat": 1682323697,
  //   "exp": 1893459661
  // }
  const resetToken =
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiIyT3JiYnhVYjhzeVp6bER6MHY1b2Z1bk8xdmkiLCJpYXQiOjE2ODIzMjM2OTcsImV4cCI6MTg5MzQ1OTY2MX0.";

  await expect(
    actions.resetPassword({
      token: resetToken,
      password: "abc",
    }),
  ).rejects.toEqual({
    code: "ERR_INVALID_INPUT",
    message: "cannot be parsed or vertified as a valid JWT",
  });
});

// This test will break if we use a private key in the test runtime.
test("reset password - valid token - password is reset", async () => {
  const identity = await models.identity.create({
    id: "2OrbbxUb8syZzlDz0v5ofunO1vi",
    email: "user@keel.xyz",
    password: "123",
  });

  // {
  //   "typ": "JWT",
  //   "alg": "none"
  // }
  // {
  //   "sub": "2OrbbxUb8syZzlDz0v5ofunO1vi",
  //   "iat": 1682323697,
  //   "exp": 1893459661,
  //   "aud": "password-reset"
  // }
  const resetToken =
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiIyT3JiYnhVYjhzeVp6bER6MHY1b2Z1bk8xdmkiLCJpYXQiOjE2ODIzMjM2OTcsImV4cCI6MTg5MzQ1OTY2MSwiYXVkIjoicGFzc3dvcmQtcmVzZXQifQ.";

  await expect(
    actions.resetPassword({
      token: resetToken,
      password: "abc",
    }),
  ).not.toHaveError({});

  await expect(
    actions.authenticate({
      createIfNotExists: false,
      emailPassword: {
        email: "user@keel.xyz",
        password: "123",
      },
    }),
  ).rejects.toEqual({
    code: "ERR_INVALID_INPUT",
    message: "failed to authenticate",
  });

  const { token } = await actions.authenticate({
    createIfNotExists: false,
    emailPassword: {
      email: "user@keel.xyz",
      password: "abc",
    },
  });

  expect(token).not.toBeNull();
});

// This test will break if we use a private key in the test runtime.
test("reset password - valid token with aud as array - password is reset", async () => {
  const identity = await models.identity.create({
    id: "2OrbbxUb8syZzlDz0v5ofunO1vi",
    email: "user@keel.xyz",
    password: "123",
  });

  // {
  //   "typ": "JWT",
  //   "alg": "none"
  // }
  // {
  //   "sub": "2OrbbxUb8syZzlDz0v5ofunO1vi",
  //   "iat": 1682323697,
  //   "exp": 1893459661,
  //   "aud": ["password-reset"]
  // }
  const resetToken =
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiIyT3JiYnhVYjhzeVp6bER6MHY1b2Z1bk8xdmkiLCJpYXQiOjE2ODIzMjM2OTcsImV4cCI6MTg5MzQ1OTY2MSwiYXVkIjpbInBhc3N3b3JkLXJlc2V0Il19.";

  await expect(
    actions.resetPassword({
      token: resetToken,
      password: "abc",
    }),
  ).not.toHaveError({});

  await expect(
    actions.authenticate({
      createIfNotExists: false,
      emailPassword: {
        email: "user@keel.xyz",
        password: "123",
      },
    }),
  ).rejects.toEqual({
    code: "ERR_INVALID_INPUT",
    message: "failed to authenticate",
  });

  const { token } = await actions.authenticate({
    createIfNotExists: false,
    emailPassword: {
      email: "user@keel.xyz",
      password: "abc",
    },
  });

  expect(token).not.toBeNull();
});

// This test will break if we use a private key in the test runtime.
test("3rd party Clerk token - identity already exists - permission satisfied", async () => {
  const identity = await models.identity.create({
    id: "2OrbbxUb8syZzlDz0v5ofunO1vi",
    externalId: "user_2OdykNxqHGHNtBA5Hcdu5Zm6vDp",
    createdBy: "https://enhanced-osprey-20.clerk.accounts.dev",
  });

  // {
  //   "typ": "JWT",
  //   "alg": "none"
  // }
  // {
  //   "azp": "http://localhost:3000",
  //   "exp": 1893459661,
  //   "iat": 1682321704,
  //   "iss": "https://enhanced-osprey-20.clerk.accounts.dev",
  //   "jti": "415f6916c6a97775c811",
  //   "nbf": 1682321699,
  //   "sub": "user_2OdykNxqHGHNtBA5Hcdu5Zm6vDp"
  // }
  const authToken =
    "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJhenAiOiJodHRwOi8vbG9jYWxob3N0OjMwMDAiLCJleHAiOjE4OTM0NTk2NjEsImlhdCI6MTY4MjMyMTcwNCwiaXNzIjoiaHR0cHM6Ly9lbmhhbmNlZC1vc3ByZXktMjAuY2xlcmsuYWNjb3VudHMuZGV2IiwianRpIjoiNDE1ZjY5MTZjNmE5Nzc3NWM4MTEiLCJuYmYiOjE2ODIzMjE2OTksInN1YiI6InVzZXJfMk9keWtOeHFIR0hOdEJBNUhjZHU1Wm02dkRwIn0.";

  const authedActions = actions.withAuthToken(authToken);

  const post = await authedActions.createPostWithIdentity({ title: "temp" });

  expect(post.identityId).equal(identity.id);

  await expect(
    authedActions.getPostRequiresIdentity({ id: post.id }),
  ).resolves.toEqual(post);
});

// This test will break if we use a private key in the test runtime.
test("3rd party Clerk token - identity does not exist - identity created and permission satisfied", async () => {
  // {
  //   "typ": "JWT",
  //   "alg": "none"
  // }
  // {
  //   "azp": "http://localhost:3000",
  //   "exp": 1893459661,
  //   "iat": 1682321704,
  //   "iss": "https://enhanced-osprey-20.clerk.accounts.dev",
  //   "jti": "415f6916c6a97775c811",
  //   "nbf": 1682321699,
  //   "sub": "user_2OdykNxqHGHNtBA5Hcdu5Zm6vDp"
  // }
  const authToken =
    "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJhenAiOiJodHRwOi8vbG9jYWxob3N0OjMwMDAiLCJleHAiOjE4OTM0NTk2NjEsImlhdCI6MTY4MjMyMTcwNCwiaXNzIjoiaHR0cHM6Ly9lbmhhbmNlZC1vc3ByZXktMjAuY2xlcmsuYWNjb3VudHMuZGV2IiwianRpIjoiNDE1ZjY5MTZjNmE5Nzc3NWM4MTEiLCJuYmYiOjE2ODIzMjE2OTksInN1YiI6InVzZXJfMk9keWtOeHFIR0hOdEJBNUhjZHU1Wm02dkRwIn0.";

  const authedActions = actions.withAuthToken(authToken);

  const post = await authedActions.createPostWithIdentity({ title: "temp" });

  const identity = await models.identity.findOne({
    id: post.identityId!,
  });

  expect(identity?.externalId).equal("user_2OdykNxqHGHNtBA5Hcdu5Zm6vDp");
  expect(identity?.createdBy).equal(
    "https://enhanced-osprey-20.clerk.accounts.dev",
  );
  expect(identity?.email).toBeNull();
  expect(identity?.password).toBeNull();

  await expect(
    authedActions.getPostRequiresIdentity({ id: post.id }),
  ).resolves.toEqual(post);
});

// This test will break if we use a private key in the test runtime.
test("3rd party Clerk token - same external id but different issuer - identity created and permission satisfied", async () => {
  const identity = await models.identity.create({
    id: "2OrbbxUb8syZzlDz0v5ofunO1vi",
    externalId: "user_2OdykNxqHGHNtBA5Hcdu5Zm6vDp",
    createdBy: "https://somewhereelse.com",
  });

  // {
  //   "typ": "JWT",
  //   "alg": "none"
  // }
  // {
  //   "azp": "http://localhost:3000",
  //   "exp": 1893459661,
  //   "iat": 1682321704,
  //   "iss": "https://enhanced-osprey-20.clerk.accounts.dev",
  //   "jti": "415f6916c6a97775c811",
  //   "nbf": 1682321699,
  //   "sub": "user_2OdykNxqHGHNtBA5Hcdu5Zm6vDp"
  // }
  const authToken =
    "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJhenAiOiJodHRwOi8vbG9jYWxob3N0OjMwMDAiLCJleHAiOjE4OTM0NTk2NjEsImlhdCI6MTY4MjMyMTcwNCwiaXNzIjoiaHR0cHM6Ly9lbmhhbmNlZC1vc3ByZXktMjAuY2xlcmsuYWNjb3VudHMuZGV2IiwianRpIjoiNDE1ZjY5MTZjNmE5Nzc3NWM4MTEiLCJuYmYiOjE2ODIzMjE2OTksInN1YiI6InVzZXJfMk9keWtOeHFIR0hOdEJBNUhjZHU1Wm02dkRwIn0.";

  const authedActions = actions.withAuthToken(authToken);

  const post = await authedActions.createPostWithIdentity({ title: "temp" });

  expect(post.identityId).not.equal(identity.id);

  await expect(
    authedActions.getPostRequiresIdentity({ id: post.id }),
  ).resolves.toEqual(post);
});
