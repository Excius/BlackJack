import SuperTokens from "supertokens-node";
import EmailPassword from "supertokens-node/recipe/emailpassword";
import Session from "supertokens-node/recipe/session";
import Dashboard from "supertokens-node/recipe/dashboard";

SuperTokens.init({
  framework: "express",
  supertokens: {
    connectionURI:
      process.env.SUPERTOKENS_CONNECTION_URI || "http://localhost:3567",
  },
  appInfo: {
    appName: "BlackJack",
    apiDomain: process.env.API_DOMAIN || "http://localhost:3001",
    websiteDomain: process.env.WEBSITE_DOMAIN || "http://localhost:3000",
  },
  recipeList: [EmailPassword.init(), Session.init(), Dashboard.init()],
});
