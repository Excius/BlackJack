import { createRoot } from "react-dom/client";
import "./index.css";
import App from "./App.tsx";
import { Provider } from "react-redux";
import { store } from "./redux/store.ts";
import SuperTokens, { SuperTokensWrapper } from "supertokens-auth-react";
import EmailPasswordReact from "supertokens-auth-react/recipe/emailpassword";
import SessionReact from "supertokens-auth-react/recipe/session";

SuperTokens.init({
  appInfo: {
    appName: "MyApp",
    apiDomain: "http://localhost:3001", // your backend API
    websiteDomain: "http://localhost:5173", // your frontend domain (Vite example)
  },
  recipeList: [EmailPasswordReact.init(), SessionReact.init()],
});

createRoot(document.getElementById("root")!).render(
  <Provider store={store}>
    <SuperTokensWrapper>
      <App />
    </SuperTokensWrapper>
  </Provider>
);
