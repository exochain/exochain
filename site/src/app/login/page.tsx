import { redirect } from 'next/navigation';
import { cookies } from 'next/headers';
import Link from 'next/link';
import { SESSION_COOKIE } from '@/lib/auth';
import { EXTRANET_ROLES, ROLE_LABEL, type ExtranetRole } from '@/lib/roles';
import { Section, Eyebrow, H1, Lede } from '@/components/ui/Section';
import { Pill } from '@/components/ui/Pill';

export const metadata = { title: 'Sign in · Extranet' };

async function signIn(formData: FormData) {
  'use server';
  const role = String(formData.get('role') ?? 'developer') as ExtranetRole;
  const next = String(formData.get('next') ?? '/app');
  const session = {
    userId: 'dev_user_001',
    email: 'dev@aperture.example',
    role,
    surface: 'extranet',
    org: 'Aperture Holdings'
  };
  cookies().set(SESSION_COOKIE, JSON.stringify(session), {
    httpOnly: true,
    sameSite: 'lax',
    path: '/',
    maxAge: 60 * 60 * 8
  });
  redirect(next);
}

async function signOut() {
  'use server';
  cookies().delete(SESSION_COOKIE);
  redirect('/app/login');
}

export default function Page({
  searchParams
}: {
  searchParams: { next?: string };
}) {
  const next = searchParams.next ?? '/app';
  return (
    <div className="min-h-dvh grid place-items-center px-6">
      <Section width="prose" className="py-12 w-full">
        <Eyebrow>Extranet · alpha</Eyebrow>
        <H1 className="mt-3">Sign in to EXOCHAIN.</H1>
        <Lede className="mt-4">
          v0 uses a dev login. Choose a role to preview the extranet under
          that capability set. Real OIDC + WebAuthn arrives in v0.5.
        </Lede>
        <div className="mt-3 flex gap-2">
          <Pill tone="signal">dev login</Pill>
          <Pill tone="custody">no real credentials</Pill>
        </div>
        <form action={signIn} className="mt-8 space-y-4">
          <input type="hidden" name="next" value={next} />
          <label className="block text-sm">
            <div className="text-eyebrow text-ink/60 dark:text-vellum-soft/60">Role</div>
            <select
              name="role"
              defaultValue="developer"
              className="mt-1 w-full border hairline rounded-sm px-3 py-2 bg-transparent"
            >
              {EXTRANET_ROLES.map((r) => (
                <option key={r} value={r}>
                  {ROLE_LABEL[r]}
                </option>
              ))}
            </select>
          </label>
          <div className="flex items-center gap-3">
            <button className="border hairline rounded-sm px-3 py-2 text-sm bg-ink text-vellum-soft">
              Sign in
            </button>
            <Link href="/" className="text-sm underline">
              Back to public site
            </Link>
          </div>
        </form>
        <form action={signOut} className="mt-3">
          <button className="text-xs underline text-ink/60 dark:text-vellum-soft/60">
            Clear session
          </button>
        </form>
      </Section>
    </div>
  );
}
