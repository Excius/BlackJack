import SuperTokens from "supertokens-node";
import EmailPassword from "supertokens-node/recipe/emailpassword";
import Session from "supertokens-node/recipe/session";
import Dashboard from "supertokens-node/recipe/dashboard";
import Passwordless from "supertokens-node/recipe/passwordless";
import ThirdPartyError from "supertokens-node/recipe/thirdparty";

SuperTokens.init({
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
    EmailPassword.init(),
    Session.init(),
    Dashboard.init(),
    Passwordless.init({
      flowType: "USER_INPUT_CODE",
      contactMethod: "EMAIL",
    }),
    ThirdPartyError.init({
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
    }),
  ],
});
