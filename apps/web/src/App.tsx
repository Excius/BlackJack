import { Suspense } from "react";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import * as reactRouterDom from "react-router-dom";
import { getSuperTokensRoutesForReactRouterDom } from "supertokens-auth-react/ui";
import { EmailPasswordPreBuiltUI } from "supertokens-auth-react/recipe/emailpassword/prebuiltui";
import Home from "./pages/Home";
import { SessionAuth } from "supertokens-auth-react/recipe/session";

const App = () => {
  return (
    <BrowserRouter>
      <Suspense fallback={<div>Loading...</div>}>
        <Routes>
          {getSuperTokensRoutesForReactRouterDom(reactRouterDom, [
            EmailPasswordPreBuiltUI,
          ])}
          <Route
            element={
              <SessionAuth>
                <Home />
              </SessionAuth>
            }
            path="/"
          />
        </Routes>
      </Suspense>
    </BrowserRouter>
  );
};

export default App;
