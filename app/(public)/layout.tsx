import { Footer, Header } from "@/components/shell";
import { SiteAnalytics } from '@/components/site-analytics';

export default function PublicLayout({ children }: { children: React.ReactNode }) {
  return (
    <>
      <SiteAnalytics />
      <Header />
      <main id="main-content" tabIndex={-1} className="container">{children}</main>
      <Footer />
    </>
  );
}
