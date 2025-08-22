import SuperTokens from "supertokens-node";
import EmailPassword from "supertokens-node/recipe/emailpassword";
import Session from "supertokens-node/recipe/session";
import Dashboard from "supertokens-node/recipe/dashboard";
import Passwordless from "supertokens-node/recipe/passwordless";
import ThirdParty from "supertokens-node/recipe/thirdparty";
import EmailVerificationClaim from "supertokens-node/recipe/emailverification";
import { prisma } from "@repo/db";

async function createAppUser(
  superTokenUserId: string,
  email: string,
  name?: string
) {
  const existing = await prisma.users.findUnique({
    where: { superTokenUserId },
  });

  if (!existing) {
    return prisma.users.create({
      data: {
        superTokenUserId,
        email,
        name,
      },
    });
  }
  return existing;
}

SuperTokens.init({
  // debug: true,
  framework: "express",
  supertokens: {
    connectionURI:
      process.env.SUPERTOKENS_CONNECTION_URI || "http://localhost:3567",
    apiKey: process.env.SUPERTOKENS_API_KEY || "my-secret-dashboard-api-key",
  },
  appInfo: {
    appName: "BlackJack",
    apiDomain: process.env.API_DOMAIN || "http://localhost:3001",
    websiteDomain: process.env.WEBSITE_DOMAIN || "http://localhost:3000",
  },
  recipeList: [
    EmailPassword.init({
      override: {
        apis: (originalImplementation) => {
          return {
            ...originalImplementation,

            signUpPOST: async function (input) {
              const emailField = input.formFields.find((f) => f.id === "email");
              const email =
                typeof emailField?.value === "string"
                  ? emailField.value
                  : undefined;

              if (!email) {
                return {
                  status: "GENERAL_ERROR",
                  message: "Email is required",
                };
              }

              const existingUsers = await SuperTokens.listUsersByAccountInfo(
                "public",
                {
                  email,
                }
              );

              if (existingUsers.length > 0) {
                const method = existingUsers[0]?.loginMethods[0]?.recipeId;

                input.options.res.setStatusCode(400);
                input.options.res.sendJSONResponse({
                  status: "EMAIL_ALREADY_EXISTS_ERROR",
                  message:
                    "An account with this email already exists via another login method.",
                  method, // send the existing method to client
                });

                return {
                  status: "GENERAL_ERROR",
                  message:
                    "An account with this email already exists via another login method.",
                  method,
                };
              }

              const result = await originalImplementation.signUpPOST!(input);

              if (result.status === "OK") {
                const email = result.user.emails[0];
                if (typeof email === "string") {
                  await createAppUser(result.user.id, email);
                }
              }

              return result;
            },
          };
        },
      },
    }),

    Session.init(),
    Dashboard.init(),
    Passwordless.init({
      flowType: "USER_INPUT_CODE",
      contactMethod: "EMAIL",
      override: {
        apis: (originalImplementation) => {
          return {
            ...originalImplementation,

            createCodePOST: async function (input) {
              // Only check for email-based login
              if ("email" in input && typeof input.email === "string") {
                const existingUsers = await SuperTokens.listUsersByAccountInfo(
                  input.tenantId,
                  { email: input.email }
                );

                if (existingUsers.length === 0) {
                  // No user exists, allow sign up
                  return originalImplementation.createCodePOST!(input);
                }

                // Check if existing user is already a passwordless user
                const hasPasswordless = existingUsers.find((user) =>
                  user.loginMethods.find(
                    (lm) =>
                      lm.hasSameEmailAs(input.email) &&
                      lm.recipeId === "passwordless"
                  )
                );

                if (hasPasswordless) {
                  // Existing user uses passwordless — allow code creation
                  return originalImplementation.createCodePOST!(input);
                }

                // Email exists with another login method → block
                input.options.res.setStatusCode(400);
                input.options.res.sendJSONResponse({
                  status: "EMAIL_ALREADY_EXISTS_ERROR",
                  message:
                    "Seems like you already have an account with another login method. Please use that instead.",
                  method: existingUsers[0]?.loginMethods[0]?.recipeId,
                });

                return {
                  status: "GENERAL_ERROR",
                  message:
                    "Seems like you already have an account with another login method. Please use that instead.",
                };
              }

              // Phone number login → allow by default
              return originalImplementation.createCodePOST!(input);
            },

            consumeCodePOST: async function (input) {
              const result =
                await originalImplementation.consumeCodePOST!(input);

              if (result.status === "OK" && result.createdNewRecipeUser) {
                const email = result.user.emails[0];
                if (typeof email === "string") {
                  await createAppUser(result.user.id, email);
                }
              }

              return result;
            },
          };
        },
      },
    }),
    ThirdParty.init({
      signInAndUpFeature: {
        providers: [
          {
            config: {
              thirdPartyId: "google",
              clients: [
                {
                  clientId:
                    process.env.GOOGLE_CLIENT_ID ||
                    "1060725074195-kmeum4crr01uirfl2op9kd5acmi9jutn.apps.googleusercontent.com",
                  clientSecret:
                    process.env.GOOGLE_CLIENT_SECRET ||
                    "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",
                },
              ],
            },
          },
          {
            config: {
              thirdPartyId: "github",
              clients: [
                {
                  clientId:
                    process.env.GITHUB_CLIENT_ID || "467101b197249757c71f",
                  clientSecret:
                    process.env.GITHUB_CLIENT_SECRET ||
                    "e97051221f4b6426e8fe8d51486396703012f5bd",
                },
              ],
            },
          },
        ],
      },
      override: {
        functions: (originalImplementation) => {
          return {
            ...originalImplementation,
            signInUp: async function (input) {
              const response = await originalImplementation.signInUp(input);

              if (response.status === "OK") {
                const email = response.user.emails?.[0];
                if (email) {
                  const existingUsers =
                    await SuperTokens.listUsersByAccountInfo(input.tenantId, {
                      email,
                    });

                  if (existingUsers.length === 0) {
                    // No existing user → allow signup
                    return response;
                  }

                  // Check if the same social login already exists
                  const sameThirdParty = existingUsers.find((user) =>
                    user.loginMethods.find(
                      (lm) =>
                        lm.hasSameThirdPartyInfoAs({
                          id: input.thirdPartyId,
                          userId: input.thirdPartyUserId,
                        }) && lm.recipeId === "thirdparty"
                    )
                  );

                  if (sameThirdParty) {
                    // Same social login → allow signup/sign-in
                    return response;
                  }

                  // Email exists with another login method → block
                  throw new Error("EMAIL_ALREADY_EXISTS_WITH_OTHER_METHOD");
                }
              }

              if (response.status === "OK" && response.createdNewRecipeUser) {
                const email = response.user.emails?.[0];
                if (typeof email === "string") {
                  await createAppUser(response.user.id, email);
                }
              }

              return response;
            },
            apis: (
              originalImplementation: import("supertokens-node/recipe/thirdparty/types").APIInterface
            ) => {
              return {
                ...originalImplementation,
                signInUpPOST: async function (
                  input: import("supertokens-node/recipe/thirdparty/types").APIInterface["signInUpPOST"] extends (
                    input: infer I
                  ) => any
                    ? I
                    : any
                ) {
                  try {
                    return await originalImplementation.signInUpPOST!(input);
                  } catch (err: any) {
                    if (
                      err.message === "EMAIL_ALREADY_EXISTS_WITH_OTHER_METHOD"
                    ) {
                      const existingUsers =
                        await SuperTokens.listUsersByAccountInfo(
                          input.tenantId,
                          { email: input.email }
                        );

                      const method =
                        existingUsers[0]?.loginMethods[0]?.recipeId;

                      input.options.res.setStatusCode(400);
                      input.options.res.sendJSONResponse({
                        status: "EMAIL_ALREADY_EXISTS_ERROR",
                        message:
                          "Seems like you already have an account with another login method. Please use that instead.",
                        method,
                      });

                      return {
                        status: "GENERAL_ERROR",
                        message:
                          "Seems like you already have an account with another login method. Please use that instead.",
                      };
                    }
                    throw err;
                  }
                },
              };
            },
          };
        },
      },
    }),
    EmailVerificationClaim.init({
      mode: "REQUIRED",
    }),
  ],
});
