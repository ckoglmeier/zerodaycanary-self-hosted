import { ConfirmPoller } from "./poller";

export const metadata = { title: "Confirming payment" };

// The return URL never grants access; this page waits for the verified webhook.
export default function Confirm() {
  return (
    <div className="stack" style={{ maxWidth: 640, ["--gap" as string]: "16px" }}>
      <h1 className="h-page">Confirming payment</h1>
      <p>Team monitoring starts when the payment provider confirms your subscription. Your first system stays free. This usually takes a few seconds.</p>
      <ConfirmPoller />
    </div>
  );
}
