import { type ClassValue, clsx } from 'clsx'
import { twMerge } from 'tailwind-merge'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

/**
 * Escape HTML special characters so the output is safe to concatenate with
 * known-good HTML (e.g. our own <strong>/<code> markdown tags) before
 * handing to React's dangerouslySetInnerHTML. Mirrors OWASP encoder and
 * lodash.escape behavior. (A-030)
 */
export function escapeHtml(input: string): string {
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}
