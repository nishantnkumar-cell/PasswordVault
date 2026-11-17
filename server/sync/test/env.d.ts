// Types `exports` from "cloudflare:workers" in the tests as this Worker.
declare namespace Cloudflare {
  interface GlobalProps {
    mainModule: typeof import("../src/index");
    durableNamespaces: "Mailbox";
  }
}
