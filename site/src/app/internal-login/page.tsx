import { redirect } from 'next/navigation';
import { cookies } from 'next/headers';
import Link from 'next/link';
import { SESSION_COOKIE } from '@/lib/auth';
import { INTRANET_ROLES, ROLE_LABEL, type IntranetRole } from '@/lib/roles';
import { Section, Eyebrow, H1, Lede } from '@/components/ui/Section';
import { Pill } from '@/components/ui/Pill';
import { Disclaimer } from '@/components/ui/Disclaimer';

export const metadata = { title: 'Sign in · Intranet' };

async function signIn(formData: FormData) {
  'use server';
  const role = String(formData.get('role') ?? 'super_admin') as IntranetRole;
  const next = String(formData.get('next') ?? '/internal');
  const session = {
    userId: 'op_user_001',
    email: 'ops@exochain.io',
    role,
    surface: 'intranet'
  };
  cookies().set(SESSION_COOKIE, JSON.stringify(session), {
    httpOnly: true,
    sameSite: 'lax',
    path: '/',
    maxAge: 60 * 60 * 4
  });
  redirect(next);
}

async function signOut() {
  'use server';
  cookies().delete(SESSION_COOKIE);
  redirect('/internal/login');
}

export default function Page({
  searchParams
}: {
  searchParams: { next?: string };
}) {
  const next = searchParams.next ?? '/internal';
  return (
    <div className="min-h-dvh grid place-items-center px-6 bg-ink text-vellum-soft">
      <Section width="prose" className="py-12 w-full">
        <Eyebrow>Intranet · internal use only</Eyebrow>
        <H1 className="mt-3 text-vellum-soft">EXOCHAIN operations</H1>
        <Lede className="mt-4 text-vellum-soft/80">
          v0 uses a dev login. Real OIDC + WebAuthn + step-up MFA arrive in
          v0.5. Choose a role to preview the intranet with that capability
          set.
        </Lede>
        <div className="mt-3 flex gap-2">
          <Pill tone="signal">dev login</Pill>
          <Pill tone="alert">step-up MFA pending</Pill>
        </div>
        <form action={signIn} className="mt-8 space-y-4">
          <input type="hidden" name="next" value={next} />
          <label className="block text-sm">
            <div className="text-eyebrow text-vellum-soft/60">Role</div>
            <select
              name="role"
              defaultValue="super_admin"
              className="mt-1 w-full border border-vellum-soft/20 rounded-sm px-3 py-2 bg-transparent"
            >
              {INTRANET_ROLES.map((r) => (
                <option key={r} value={r}>
                  {ROLE_LABEL[r]}
                </option>
              ))}
            </select>
          </label>
          <div className="flex items-center gap-3">
            <button className="border border-vellum-soft/40 rounded-sm px-3 py-2 text-sm bg-vellum-soft text-ink">
              Sign in
            </button>
            <Link href="/" className="text-sm underline text-vellum-soft/80">
              Back to public site
            </Link>
          </div>
        </form>
        <form action={signOut} className="mt-3">
          <button className="text-xs underline text-vellum-soft/60">
            Clear session
          </button>
        </form>
        <div className="mt-8">
          <Disclaimer>
            All intranet actions are recorded in append-only audit logs and
            reviewed by internal audit and security.
          </Disclaimer>
        </div>
      </Section>
    </div>
  );
}
