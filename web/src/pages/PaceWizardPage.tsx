// Copyright 2026 Exochain Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

/** PaceWizardPage — One-time crawl-through wizard for PACE enrollment.
 *
 *  Guides the user through Shamir's Secret Sharing key sharding
 *  with a minimum of 4 PACE contacts (trustees). Each step is
 *  maximally instructional — the wizard simultaneously teaches
 *  the user about PACE, key sovereignty, and governance identity
 *  while they complete the setup.
 *
 *  Steps:
 *   1. Welcome & Sovereignty Brief
 *   2. Generate Master Key (or import)
 *   3. Add PACE Contacts (minimum 4)
 *   4. Configure Threshold (3-of-N default)
 *   5. Generate & Distribute Shares
 *   6. Confirm Receipt from Contacts
 *   7. Finalize Enrollment
 */

import { useState, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../lib/auth'
import { cn } from '../lib/utils'
import { useCouncil } from '../lib/CouncilContext'

// ─── Types ───────────────────────────────────────────────────────────────────

type ContactRelationship = 'family' | 'friend' | 'colleague' | 'legal' | 'institutional'

interface PaceContact {
  id: string
  displayName: string
  did: string
  relationship: ContactRelationship
  email: string
  shareDistributed: boolean
  confirmedReceipt: boolean
}

interface ShamirConfig {
  threshold: number
  totalShares: number
}

interface SharePreview {
  contactId: string
  contactName: string
  shareIndex: number
  shareHash: string // truncated hash for visual verification
}

type WizardStep = 0 | 1 | 2 | 3 | 4 | 5 | 6

// ─── Step metadata ───────────────────────────────────────────────────────────

const STEP_INFO: { title: string; subtitle: string }[] = [
  { title: 'Key Sovereignty', subtitle: 'Understanding your governance identity' },
  { title: 'Master Key', subtitle: 'Generate your cryptographic identity' },
  { title: 'PACE Contacts', subtitle: 'Designate your trusted key holders' },
  { title: 'Threshold Config', subtitle: 'Set your recovery parameters' },
  { title: 'Share Generation', subtitle: 'Split your key into Shamir shares' },
  { title: 'Distribution', subtitle: 'Send shares to your contacts' },
  { title: 'Finalize', subtitle: 'Complete your PACE enrollment' },
]

const RELATIONSHIP_LABELS: Record<ContactRelationship, string> = {
  family: 'Family Member',
  friend: 'Trusted Friend',
  colleague: 'Professional Colleague',
  legal: 'Legal Representative',
  institutional: 'Institutional Custodian',
}

// ─── Utility ─────────────────────────────────────────────────────────────────

function generateId(): string {
  return `pc-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
}

function generateFakeShareHash(): string {
  const chars = '0123456789abcdef'
  let hash = ''
  for (let i = 0; i < 16; i++) hash += chars[Math.floor(Math.random() * 16)]
  return hash
}

// ─── Component ───────────────────────────────────────────────────────────────

export function PaceWizardPage() {
  const navigate = useNavigate()
  const { user } = useAuth()
  const { openPanel } = useCouncil()

  const [step, setStep] = useState<WizardStep>(0)
  const [contacts, setContacts] = useState<PaceContact[]>([])
  const [shamirConfig, setShamirConfig] = useState<ShamirConfig>({ threshold: 3, totalShares: 4 })
  const [keyGenerated, setKeyGenerated] = useState(false)
  const [shares, setShares] = useState<SharePreview[]>([])
  const [enrollmentComplete, setEnrollmentComplete] = useState(false)

  // Contact form state
  const [newContact, setNewContact] = useState({ displayName: '', did: '', email: '', relationship: 'friend' as ContactRelationship })

  const canProceed = useCallback((): boolean => {
    switch (step) {
      case 0: return true // Welcome — always can proceed
      case 1: return keyGenerated
      case 2: return contacts.length >= 4
      case 3: return shamirConfig.threshold >= 2 && shamirConfig.threshold < shamirConfig.totalShares
      case 4: return shares.length > 0
      case 5: return contacts.every(c => c.shareDistributed && c.confirmedReceipt)
      case 6: return true
      default: return false
    }
  }, [step, keyGenerated, contacts, shamirConfig, shares])

  const nextStep = useCallback(() => {
    if (step < 6) setStep((step + 1) as WizardStep)
  }, [step])

  const prevStep = useCallback(() => {
    if (step > 0) setStep((step - 1) as WizardStep)
  }, [step])

  const addContact = useCallback(() => {
    if (!newContact.displayName.trim()) return
    const contact: PaceContact = {
      id: generateId(),
      displayName: newContact.displayName.trim(),
      did: newContact.did.trim() || `did:exo:pending-${Date.now()}`,
      email: newContact.email.trim(),
      relationship: newContact.relationship,
      shareDistributed: false,
      confirmedReceipt: false,
    }
    setContacts(prev => [...prev, contact])
    setShamirConfig(prev => ({ ...prev, totalShares: contacts.length + 1 >= 4 ? contacts.length + 1 : 4 }))
    setNewContact({ displayName: '', did: '', email: '', relationship: 'friend' })
  }, [newContact, contacts.length])

  const removeContact = useCallback((id: string) => {
    setContacts(prev => prev.filter(c => c.id !== id))
  }, [])

  const generateKey = useCallback(() => {
    // Simulate key generation (in production, uses Web Crypto API + backend)
    setKeyGenerated(true)
  }, [])

  const generateShares = useCallback(() => {
    const previews: SharePreview[] = contacts.map((c, i) => ({
      contactId: c.id,
      contactName: c.displayName,
      shareIndex: i + 1,
      shareHash: generateFakeShareHash(),
    }))
    setShares(previews)
  }, [contacts])

  const markDistributed = useCallback((contactId: string) => {
    setContacts(prev => prev.map(c =>
      c.id === contactId ? { ...c, shareDistributed: true } : c
    ))
  }, [])

  const markConfirmed = useCallback((contactId: string) => {
    setContacts(prev => prev.map(c =>
      c.id === contactId ? { ...c, confirmedReceipt: true } : c
    ))
  }, [])

  const finalize = useCallback(() => {
    setEnrollmentComplete(true)
    // In production: POST to /api/v1/pace/finalize
  }, [])

  if (!user) return null

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-[var(--text-primary)]">PACE Enrollment</h1>
          <p className="text-sm text-[var(--text-secondary)] mt-1">
            Secure your governance identity with Shamir's Secret Sharing
          </p>
        </div>
        <button
          onClick={() => openPanel('pace-wizard')}
          className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm font-medium text-violet-600 bg-violet-50 hover:bg-violet-100 border border-violet-200 transition-colors"
        >
          <svg className="w-4 h-4" viewBox="0 0 24 24" fill="currentColor">
            <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z" />
          </svg>
          Ask Council AI
        </button>
      </div>

      {/* Progress bar */}
      <div className="bg-[var(--surface-raised)] rounded-xl border border-[var(--border-subtle)] p-4">
        <div className="flex items-center justify-between mb-3">
          {STEP_INFO.map((info, i) => (
            <div key={i} className="flex items-center">
              <div className="flex flex-col items-center">
                <div className={cn(
                  'w-9 h-9 rounded-full flex items-center justify-center text-xs font-bold border-2 transition-all',
                  i < step ? 'border-green-500 bg-green-500 text-white'
                    : i === step ? 'border-[var(--accent-primary)] bg-[var(--accent-muted)] text-[var(--accent-primary)] ring-2 ring-[var(--accent-primary)]/20'
                    : 'border-[var(--border-subtle)] bg-[var(--surface-overlay)] text-[var(--text-muted)]'
                )}>
                  {i < step ? (
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M5 13l4 4L19 7" />
                    </svg>
                  ) : (
                    i + 1
                  )}
                </div>
                <span className={cn(
                  'mt-1 text-2xs font-medium hidden tablet:block max-w-[80px] text-center leading-tight',
                  i <= step ? 'text-[var(--text-primary)]' : 'text-[var(--text-muted)]'
                )}>
                  {info.title}
                </span>
              </div>
              {i < STEP_INFO.length - 1 && (
                <div className={cn(
                  'w-6 tablet:w-10 desktop:w-16 h-0.5 mx-1 mb-4 tablet:mb-0',
                  i < step ? 'bg-green-500' : 'bg-[var(--border-subtle)]'
                )} />
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Step content */}
      <div className="bg-[var(--surface-raised)] rounded-xl border border-[var(--border-subtle)] overflow-hidden">
        {/* Step header */}
        <div className="px-6 py-4 border-b border-[var(--border-subtle)] bg-gradient-to-r from-blue-600/5 to-violet-600/5">
          <h2 className="text-lg font-bold text-[var(--text-primary)]">{STEP_INFO[step].title}</h2>
          <p className="text-sm text-[var(--text-secondary)]">{STEP_INFO[step].subtitle}</p>
        </div>

        <div className="p-6">
          {/* STEP 0: Welcome & Sovereignty Brief */}
          {step === 0 && (
            <div className="space-y-6">
              <div className="prose prose-sm max-w-none text-[var(--text-primary)]">
                <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 mb-4">
                  <h3 className="text-base font-bold text-blue-900 mt-0 mb-2">Why PACE Enrollment?</h3>
                  <p className="text-sm text-blue-800 mb-0">
                    Your governance identity is your most critical asset. PACE enrollment ensures
                    your cryptographic key — the root of all your votes, delegations, and decisions —
                    can never be permanently lost, while remaining under <strong>your sovereign control</strong>.
                  </p>
                </div>

                <div className="grid grid-cols-1 tablet:grid-cols-2 gap-4">
                  <InfoCard
                    letter="P"
                    title="Provable"
                    description="Your identity is anchored to a cryptographic key pair. You can prove you are who you claim — no central authority needed."
                    color="blue"
                  />
                  <InfoCard
                    letter="A"
                    title="Auditable"
                    description="Every action you take is signed and logged in the tamper-evident audit chain. Your trustees hold shares of your key for recovery."
                    color="indigo"
                  />
                  <InfoCard
                    letter="C"
                    title="Compliant"
                    description="Your identity meets governance compliance requirements: key escrow via Shamir sharing, verified contact relationships, attestation chain."
                    color="violet"
                  />
                  <InfoCard
                    letter="E"
                    title="Enforceable"
                    description="Full PACE enrollment makes your governance actions enforceable — your votes count at maximum weight, you can hold delegated authority."
                    color="purple"
                  />
                </div>

                <div className="bg-amber-50 border border-amber-200 rounded-lg p-4 mt-4">
                  <h4 className="text-sm font-bold text-amber-900 mt-0 mb-1">What is Shamir's Secret Sharing?</h4>
                  <p className="text-sm text-amber-800 mb-0">
                    Your master key is mathematically split into <strong>N shares</strong> distributed to your
                    trusted contacts. Any <strong>K-of-N</strong> shares can reconstruct your key (default: 3-of-4).
                    No single contact can access your identity alone. If you lose your key, your
                    contacts can help you recover — but only if enough of them cooperate.
                  </p>
                </div>
              </div>
            </div>
          )}

          {/* STEP 1: Generate Master Key */}
          {step === 1 && (
            <div className="space-y-6">
              <div className="bg-slate-50 border border-slate-200 rounded-lg p-4">
                <h3 className="text-sm font-bold text-slate-900 mb-2">Your Governance Key</h3>
                <p className="text-sm text-slate-600 mb-3">
                  This generates an <strong>Ed25519 key pair</strong> — the same cryptographic primitive used
                  throughout EXOCHAIN for signing events, votes, and delegations. Your public key
                  becomes your DID (Decentralized Identifier). Your private key never leaves this device
                  until it's split into Shamir shares.
                </p>

                {keyGenerated ? (
                  <div className="space-y-3">
                    <div className="flex items-center gap-2 text-green-700 bg-green-50 rounded-lg p-3 border border-green-200">
                      <svg className="w-5 h-5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                      </svg>
                      <span className="text-sm font-medium">Key pair generated successfully</span>
                    </div>

                    <div className="bg-white rounded-lg p-3 border border-slate-200">
                      <div className="text-xs text-slate-500 mb-1">Your DID</div>
                      <code className="text-xs font-mono text-slate-800 break-all">{user.did}</code>
                    </div>

                    <div className="bg-white rounded-lg p-3 border border-slate-200">
                      <div className="text-xs text-slate-500 mb-1">Algorithm</div>
                      <code className="text-xs font-mono text-slate-800">Ed25519 (256-bit)</code>
                    </div>

                    <div className="bg-white rounded-lg p-3 border border-slate-200">
                      <div className="text-xs text-slate-500 mb-1">Key Derivation</div>
                      <code className="text-xs font-mono text-slate-800">BLAKE3(pubkey)[0..20] → Base58 → did:exo:*</code>
                    </div>
                  </div>
                ) : (
                  <div className="text-center py-6">
                    <div className="w-20 h-20 mx-auto mb-4 rounded-full bg-gradient-to-br from-blue-500 to-violet-500 flex items-center justify-center">
                      <svg className="w-10 h-10 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
                      </svg>
                    </div>
                    <button
                      onClick={generateKey}
                      className="px-6 py-2.5 rounded-lg bg-[var(--accent-primary)] text-white font-semibold text-sm hover:bg-[var(--accent-hover)] transition-colors"
                    >
                      Generate Master Key
                    </button>
                    <p className="text-xs text-slate-500 mt-2">Uses Web Crypto API + CSPRNG for key generation</p>
                  </div>
                )}
              </div>

              <div className="bg-red-50 border border-red-200 rounded-lg p-4">
                <div className="flex items-start gap-2">
                  <svg className="w-5 h-5 text-red-600 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                  </svg>
                  <div>
                    <h4 className="text-sm font-bold text-red-900 mb-1">Critical Security Note</h4>
                    <p className="text-xs text-red-700">
                      Your private key is <strong>never transmitted over the network</strong>. It exists only
                      in your browser's secure memory until it's split into Shamir shares and
                      distributed to your PACE contacts. After sharding, the original key is
                      securely erased from this session.
                    </p>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* STEP 2: Add PACE Contacts */}
          {step === 2 && (
            <div className="space-y-6">
              <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
                <h3 className="text-sm font-bold text-blue-900 mb-1">Designate Your Key Holders</h3>
                <p className="text-sm text-blue-800">
                  Choose at least <strong>4 trusted contacts</strong> who will each hold a share of your
                  key. These should be people you trust with your governance identity — they cannot
                  access your key individually, but a threshold group can reconstruct it for recovery.
                </p>
              </div>

              {/* Contact list */}
              <div className="space-y-2">
                {contacts.map((contact, i) => (
                  <div key={contact.id} className="flex items-center gap-3 p-3 rounded-lg bg-[var(--surface-overlay)] border border-[var(--border-subtle)]">
                    <div className="w-10 h-10 rounded-full bg-gradient-to-br from-blue-400 to-violet-400 flex items-center justify-center text-white font-bold text-sm flex-shrink-0">
                      {contact.displayName.charAt(0).toUpperCase()}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-semibold text-[var(--text-primary)]">{contact.displayName}</span>
                        <span className="text-2xs px-1.5 py-0.5 rounded-full bg-slate-100 text-slate-600 font-medium">
                          {RELATIONSHIP_LABELS[contact.relationship]}
                        </span>
                        <span className="text-2xs text-[var(--text-muted)]">Share #{i + 1}</span>
                      </div>
                      <div className="text-xs text-[var(--text-muted)] truncate">{contact.email || contact.did}</div>
                    </div>
                    <button
                      onClick={() => removeContact(contact.id)}
                      className="p-1.5 rounded-lg text-red-400 hover:text-red-600 hover:bg-red-50 transition-colors"
                      aria-label={`Remove ${contact.displayName}`}
                    >
                      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                      </svg>
                    </button>
                  </div>
                ))}

                {contacts.length < 4 && (
                  <div className="text-center py-2">
                    <span className="text-xs text-amber-600 font-medium">
                      {4 - contacts.length} more contact{4 - contacts.length !== 1 ? 's' : ''} needed (minimum 4)
                    </span>
                  </div>
                )}
              </div>

              {/* Add contact form */}
              <div className="border border-dashed border-[var(--border-subtle)] rounded-lg p-4 space-y-3">
                <h4 className="text-sm font-semibold text-[var(--text-primary)]">Add PACE Contact</h4>
                <div className="grid grid-cols-1 tablet:grid-cols-2 gap-3">
                  <div>
                    <label className="block text-xs font-medium text-[var(--text-secondary)] mb-1">Display Name *</label>
                    <input
                      type="text"
                      value={newContact.displayName}
                      onChange={e => setNewContact(prev => ({ ...prev, displayName: e.target.value }))}
                      placeholder="Jane Doe"
                      className="w-full px-3 py-2 text-sm rounded-lg border border-[var(--border-subtle)] bg-[var(--surface-widget)] text-[var(--text-primary)] focus:outline-none focus:ring-2 focus:ring-[var(--accent-primary)]"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-[var(--text-secondary)] mb-1">Email</label>
                    <input
                      type="email"
                      value={newContact.email}
                      onChange={e => setNewContact(prev => ({ ...prev, email: e.target.value }))}
                      placeholder="jane@example.com"
                      className="w-full px-3 py-2 text-sm rounded-lg border border-[var(--border-subtle)] bg-[var(--surface-widget)] text-[var(--text-primary)] focus:outline-none focus:ring-2 focus:ring-[var(--accent-primary)]"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-[var(--text-secondary)] mb-1">DID (optional)</label>
                    <input
                      type="text"
                      value={newContact.did}
                      onChange={e => setNewContact(prev => ({ ...prev, did: e.target.value }))}
                      placeholder="did:exo:..."
                      className="w-full px-3 py-2 text-sm rounded-lg border border-[var(--border-subtle)] bg-[var(--surface-widget)] text-[var(--text-primary)] focus:outline-none focus:ring-2 focus:ring-[var(--accent-primary)] font-mono text-xs"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-[var(--text-secondary)] mb-1">Relationship</label>
                    <select
                      value={newContact.relationship}
                      onChange={e => setNewContact(prev => ({ ...prev, relationship: e.target.value as ContactRelationship }))}
                      className="w-full px-3 py-2 text-sm rounded-lg border border-[var(--border-subtle)] bg-[var(--surface-widget)] text-[var(--text-primary)] focus:outline-none focus:ring-2 focus:ring-[var(--accent-primary)]"
                    >
                      {(Object.entries(RELATIONSHIP_LABELS) as [ContactRelationship, string][]).map(([key, label]) => (
                        <option key={key} value={key}>{label}</option>
                      ))}
                    </select>
                  </div>
                </div>
                <button
                  onClick={addContact}
                  disabled={!newContact.displayName.trim()}
                  className="px-4 py-2 rounded-lg bg-[var(--accent-primary)] text-white text-sm font-medium hover:bg-[var(--accent-hover)] disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                >
                  + Add Contact
                </button>
              </div>

              {/* Diversity guidance */}
              <div className="bg-violet-50 border border-violet-200 rounded-lg p-4">
                <h4 className="text-sm font-bold text-violet-900 mb-1">Contact Diversity Best Practice</h4>
                <p className="text-xs text-violet-700">
                  For maximum security, choose contacts across <strong>different relationship types</strong> and
                  <strong> geographic locations</strong>. Avoid having all contacts in the same family, company,
                  or jurisdiction. This protects against correlated failure modes (e.g., a single legal
                  event affecting multiple contacts simultaneously).
                </p>
              </div>
            </div>
          )}

          {/* STEP 3: Threshold Configuration */}
          {step === 3 && (
            <div className="space-y-6">
              <div className="bg-slate-50 border border-slate-200 rounded-lg p-4">
                <h3 className="text-sm font-bold text-slate-900 mb-2">Recovery Threshold</h3>
                <p className="text-sm text-slate-600">
                  The threshold determines how many contacts must cooperate to reconstruct your key.
                  A higher threshold means more security but harder recovery. A lower threshold
                  means easier recovery but more trust required per contact.
                </p>
              </div>

              <div className="grid grid-cols-1 tablet:grid-cols-2 gap-6">
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-semibold text-[var(--text-primary)] mb-2">
                      Threshold (K): {shamirConfig.threshold} of {contacts.length}
                    </label>
                    <input
                      type="range"
                      min={2}
                      max={Math.max(2, contacts.length - 1)}
                      value={shamirConfig.threshold}
                      onChange={e => setShamirConfig(prev => ({ ...prev, threshold: parseInt(e.target.value) }))}
                      className="w-full accent-[var(--accent-primary)]"
                    />
                    <div className="flex justify-between text-2xs text-[var(--text-muted)] mt-1">
                      <span>2 (easier recovery)</span>
                      <span>{contacts.length - 1} (more secure)</span>
                    </div>
                  </div>

                  <div className="bg-white rounded-lg p-4 border border-[var(--border-subtle)]">
                    <div className="text-sm font-semibold text-[var(--text-primary)] mb-2">Configuration</div>
                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between">
                        <span className="text-[var(--text-secondary)]">Total shares</span>
                        <span className="font-mono font-semibold">{contacts.length}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-[var(--text-secondary)]">Recovery threshold</span>
                        <span className="font-mono font-semibold">{shamirConfig.threshold}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-[var(--text-secondary)]">Max contacts that can fail</span>
                        <span className="font-mono font-semibold text-amber-600">{contacts.length - shamirConfig.threshold}</span>
                      </div>
                    </div>
                  </div>
                </div>

                <div className="space-y-3">
                  <div className="text-sm font-semibold text-[var(--text-primary)]">Security Analysis</div>
                  <SecurityBar
                    label="Collusion resistance"
                    value={shamirConfig.threshold}
                    max={contacts.length}
                    description={`${shamirConfig.threshold} contacts must conspire to access your key`}
                  />
                  <SecurityBar
                    label="Recovery resilience"
                    value={contacts.length - shamirConfig.threshold}
                    max={contacts.length}
                    description={`You can lose ${contacts.length - shamirConfig.threshold} contact${contacts.length - shamirConfig.threshold !== 1 ? 's' : ''} and still recover`}
                  />
                  <SecurityBar
                    label="Availability"
                    value={Math.round(((contacts.length - shamirConfig.threshold + 1) / contacts.length) * 100)}
                    max={100}
                    description={`${Math.round(((contacts.length - shamirConfig.threshold + 1) / contacts.length) * 100)}% probability of recovery if contacts are independently available`}
                    isPercent
                  />
                </div>
              </div>

              <div className="bg-green-50 border border-green-200 rounded-lg p-4">
                <h4 className="text-sm font-bold text-green-900 mb-1">Recommended: {Math.min(3, contacts.length - 1)}-of-{contacts.length}</h4>
                <p className="text-xs text-green-700">
                  For {contacts.length} contacts, we recommend a threshold of <strong>{Math.min(3, contacts.length - 1)}</strong>.
                  This balances security (majority required) with recovery (can lose {contacts.length - Math.min(3, contacts.length - 1)} contact{contacts.length - Math.min(3, contacts.length - 1) !== 1 ? 's' : ''}).
                </p>
              </div>
            </div>
          )}

          {/* STEP 4: Generate Shares */}
          {step === 4 && (
            <div className="space-y-6">
              <div className="bg-slate-50 border border-slate-200 rounded-lg p-4">
                <h3 className="text-sm font-bold text-slate-900 mb-2">Share Generation</h3>
                <p className="text-sm text-slate-600">
                  Your master key will be split into {contacts.length} shares using a degree-{shamirConfig.threshold - 1} polynomial
                  over GF(256). Each share is independently meaningless — only {shamirConfig.threshold} or more
                  shares can reconstruct the original key via Lagrange interpolation.
                </p>
              </div>

              {shares.length === 0 ? (
                <div className="text-center py-8">
                  <div className="w-24 h-24 mx-auto mb-4 rounded-full bg-gradient-to-br from-indigo-500 to-purple-500 flex items-center justify-center">
                    <svg className="w-12 h-12 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4" />
                    </svg>
                  </div>
                  <p className="text-sm text-[var(--text-secondary)] mb-4">
                    Ready to generate {contacts.length} Shamir shares with threshold {shamirConfig.threshold}
                  </p>
                  <button
                    onClick={generateShares}
                    className="px-8 py-3 rounded-lg bg-gradient-to-r from-indigo-600 to-purple-600 text-white font-semibold text-sm hover:from-indigo-700 hover:to-purple-700 transition-all shadow-lg"
                  >
                    Generate Shares
                  </button>
                </div>
              ) : (
                <div className="space-y-3">
                  <div className="flex items-center gap-2 text-green-700 bg-green-50 rounded-lg p-3 border border-green-200">
                    <svg className="w-5 h-5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    <span className="text-sm font-medium">{shares.length} shares generated successfully</span>
                  </div>

                  {shares.map(share => (
                    <div key={share.contactId} className="flex items-center gap-3 p-3 rounded-lg bg-[var(--surface-overlay)] border border-[var(--border-subtle)]">
                      <div className="w-8 h-8 rounded-lg bg-indigo-100 text-indigo-700 flex items-center justify-center text-xs font-bold">
                        #{share.shareIndex}
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="text-sm font-medium text-[var(--text-primary)]">{share.contactName}</div>
                        <div className="text-xs text-[var(--text-muted)] font-mono">
                          Verification: {share.shareHash}
                        </div>
                      </div>
                      <div className="text-xs text-green-600 font-semibold">Ready</div>
                    </div>
                  ))}

                  <div className="bg-amber-50 border border-amber-200 rounded-lg p-3">
                    <p className="text-xs text-amber-700">
                      <strong>Important:</strong> The original master key will be securely erased from this
                      session after distribution. Keep these shares safe — they are the only way to
                      recover your governance identity.
                    </p>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* STEP 5: Distribution */}
          {step === 5 && (
            <div className="space-y-6">
              <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
                <h3 className="text-sm font-bold text-blue-900 mb-1">Distribute Shares</h3>
                <p className="text-sm text-blue-800">
                  Send each share to its designated contact. Use a <strong>secure channel</strong> — encrypted
                  email, in-person handoff, or the EXOCHAIN secure messaging system. After sending,
                  mark each share as distributed and wait for your contact to confirm receipt.
                </p>
              </div>

              <div className="space-y-3">
                {contacts.map((contact, i) => {
                  const share = shares.find(s => s.contactId === contact.id)
                  return (
                    <div key={contact.id} className={cn(
                      'p-4 rounded-lg border transition-all',
                      contact.confirmedReceipt
                        ? 'bg-green-50 border-green-200'
                        : contact.shareDistributed
                          ? 'bg-amber-50 border-amber-200'
                          : 'bg-[var(--surface-overlay)] border-[var(--border-subtle)]'
                    )}>
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center gap-3">
                          <div className={cn(
                            'w-10 h-10 rounded-full flex items-center justify-center text-white font-bold text-sm',
                            contact.confirmedReceipt ? 'bg-green-500' : contact.shareDistributed ? 'bg-amber-500' : 'bg-slate-400'
                          )}>
                            {contact.confirmedReceipt ? (
                              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M5 13l4 4L19 7" />
                              </svg>
                            ) : (
                              <span>{i + 1}</span>
                            )}
                          </div>
                          <div>
                            <div className="text-sm font-semibold text-[var(--text-primary)]">{contact.displayName}</div>
                            <div className="text-xs text-[var(--text-muted)]">
                              {RELATIONSHIP_LABELS[contact.relationship]} &middot; Share #{i + 1}
                              {share && <> &middot; <code className="font-mono">{share.shareHash.slice(0, 8)}...</code></>}
                            </div>
                          </div>
                        </div>

                        <div className="flex items-center gap-2">
                          {!contact.shareDistributed && (
                            <button
                              onClick={() => markDistributed(contact.id)}
                              className="px-3 py-1.5 rounded-lg text-xs font-medium bg-blue-600 text-white hover:bg-blue-700 transition-colors"
                            >
                              Mark Sent
                            </button>
                          )}
                          {contact.shareDistributed && !contact.confirmedReceipt && (
                            <button
                              onClick={() => markConfirmed(contact.id)}
                              className="px-3 py-1.5 rounded-lg text-xs font-medium bg-green-600 text-white hover:bg-green-700 transition-colors"
                            >
                              Confirm Receipt
                            </button>
                          )}
                          {contact.confirmedReceipt && (
                            <span className="text-xs font-semibold text-green-700">Confirmed</span>
                          )}
                        </div>
                      </div>

                      {/* Status bar */}
                      <div className="flex items-center gap-2 mt-2">
                        <div className="flex-1 h-1.5 bg-slate-200 rounded-full overflow-hidden">
                          <div
                            className={cn(
                              'h-full rounded-full transition-all',
                              contact.confirmedReceipt ? 'bg-green-500 w-full'
                                : contact.shareDistributed ? 'bg-amber-500 w-1/2'
                                : 'bg-slate-300 w-0'
                            )}
                          />
                        </div>
                        <span className="text-2xs text-[var(--text-muted)]">
                          {contact.confirmedReceipt ? 'Complete' : contact.shareDistributed ? 'Awaiting confirmation' : 'Pending'}
                        </span>
                      </div>
                    </div>
                  )
                })}
              </div>

              {/* Progress summary */}
              <div className="bg-slate-50 border border-slate-200 rounded-lg p-4">
                <div className="flex justify-between text-sm">
                  <span className="text-[var(--text-secondary)]">Distributed</span>
                  <span className="font-semibold">{contacts.filter(c => c.shareDistributed).length} / {contacts.length}</span>
                </div>
                <div className="flex justify-between text-sm mt-1">
                  <span className="text-[var(--text-secondary)]">Confirmed</span>
                  <span className="font-semibold">{contacts.filter(c => c.confirmedReceipt).length} / {contacts.length}</span>
                </div>
              </div>
            </div>
          )}

          {/* STEP 6: Finalize */}
          {step === 6 && (
            <div className="space-y-6">
              {enrollmentComplete ? (
                <div className="text-center py-8 space-y-4">
                  <div className="w-24 h-24 mx-auto rounded-full bg-gradient-to-br from-green-400 to-emerald-500 flex items-center justify-center shadow-lg">
                    <svg className="w-12 h-12 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                    </svg>
                  </div>
                  <h3 className="text-xl font-bold text-[var(--text-primary)]">PACE Enrollment Complete</h3>
                  <p className="text-sm text-[var(--text-secondary)] max-w-md mx-auto">
                    Your governance identity is now fully secured with Shamir's Secret Sharing.
                    Your {contacts.length} PACE contacts hold shares with a {shamirConfig.threshold}-of-{contacts.length} recovery threshold.
                  </p>

                  <div className="grid grid-cols-2 tablet:grid-cols-4 gap-3 max-w-lg mx-auto mt-6">
                    {['Provable', 'Auditable', 'Compliant', 'Enforceable'].map(stage => (
                      <div key={stage} className="bg-green-50 border border-green-200 rounded-lg p-3 text-center">
                        <svg className="w-6 h-6 text-green-500 mx-auto mb-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                        </svg>
                        <span className="text-xs font-semibold text-green-700">{stage}</span>
                      </div>
                    ))}
                  </div>

                  <button
                    onClick={() => navigate('/identity')}
                    className="mt-6 px-6 py-2.5 rounded-lg bg-[var(--accent-primary)] text-white font-semibold text-sm hover:bg-[var(--accent-hover)] transition-colors"
                  >
                    View Your Identity
                  </button>
                </div>
              ) : (
                <div className="space-y-4">
                  <div className="bg-green-50 border border-green-200 rounded-lg p-4">
                    <h3 className="text-sm font-bold text-green-900 mb-2">Ready to Finalize</h3>
                    <p className="text-sm text-green-800">
                      All {contacts.length} shares have been distributed and confirmed. Your governance
                      identity will be elevated to <strong>Enforceable</strong> status — the highest
                      PACE tier.
                    </p>
                  </div>

                  {/* Summary */}
                  <div className="grid grid-cols-1 tablet:grid-cols-2 gap-4">
                    <div className="bg-[var(--surface-overlay)] rounded-lg p-4 border border-[var(--border-subtle)]">
                      <div className="text-xs text-[var(--text-muted)] mb-1">Identity</div>
                      <code className="text-xs font-mono text-[var(--text-primary)] break-all">{user.did}</code>
                    </div>
                    <div className="bg-[var(--surface-overlay)] rounded-lg p-4 border border-[var(--border-subtle)]">
                      <div className="text-xs text-[var(--text-muted)] mb-1">Shamir Config</div>
                      <div className="text-sm font-semibold text-[var(--text-primary)]">{shamirConfig.threshold}-of-{contacts.length} threshold</div>
                    </div>
                    <div className="bg-[var(--surface-overlay)] rounded-lg p-4 border border-[var(--border-subtle)]">
                      <div className="text-xs text-[var(--text-muted)] mb-1">Contacts</div>
                      <div className="text-sm font-semibold text-[var(--text-primary)]">{contacts.length} PACE trustees</div>
                    </div>
                    <div className="bg-[var(--surface-overlay)] rounded-lg p-4 border border-[var(--border-subtle)]">
                      <div className="text-xs text-[var(--text-muted)] mb-1">Resulting PACE Level</div>
                      <div className="text-sm font-semibold text-green-600">Enforceable</div>
                    </div>
                  </div>

                  <div className="text-center pt-4">
                    <button
                      onClick={finalize}
                      className="px-8 py-3 rounded-lg bg-gradient-to-r from-green-600 to-emerald-600 text-white font-bold text-sm hover:from-green-700 hover:to-emerald-700 transition-all shadow-lg"
                    >
                      Finalize PACE Enrollment
                    </button>
                  </div>

                  <div className="bg-amber-50 border border-amber-200 rounded-lg p-3">
                    <p className="text-xs text-amber-700 text-center">
                      <strong>This action is irreversible.</strong> Your master key will be securely erased.
                      Key recovery will only be possible through your PACE contacts.
                    </p>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Navigation buttons */}
        <div className="px-6 py-4 border-t border-[var(--border-subtle)] flex items-center justify-between">
          <button
            onClick={prevStep}
            disabled={step === 0}
            className="px-4 py-2 rounded-lg text-sm font-medium text-[var(--text-secondary)] hover:bg-[var(--surface-overlay)] disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
          >
            Back
          </button>

          <div className="text-xs text-[var(--text-muted)]">
            Step {step + 1} of {STEP_INFO.length}
          </div>

          {step < 6 ? (
            <button
              onClick={nextStep}
              disabled={!canProceed()}
              className="px-4 py-2 rounded-lg text-sm font-medium bg-[var(--accent-primary)] text-white hover:bg-[var(--accent-hover)] disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
            >
              Continue
            </button>
          ) : (
            !enrollmentComplete && (
              <button
                onClick={finalize}
                className="px-4 py-2 rounded-lg text-sm font-medium bg-green-600 text-white hover:bg-green-700 transition-colors"
              >
                Finalize
              </button>
            )
          )}
        </div>
      </div>
    </div>
  )
}

// ─── Sub-components ──────────────────────────────────────────────────────────

function InfoCard({ letter, title, description, color }: {
  letter: string
  title: string
  description: string
  color: string
}) {
  const colorMap: Record<string, string> = {
    blue: 'bg-blue-100 text-blue-700 border-blue-200',
    indigo: 'bg-indigo-100 text-indigo-700 border-indigo-200',
    violet: 'bg-violet-100 text-violet-700 border-violet-200',
    purple: 'bg-purple-100 text-purple-700 border-purple-200',
  }

  return (
    <div className={cn('rounded-lg p-4 border', colorMap[color])}>
      <div className="flex items-center gap-2 mb-2">
        <div className="w-8 h-8 rounded-full bg-current/10 flex items-center justify-center font-bold text-lg">
          {letter}
        </div>
        <h4 className="font-bold text-sm">{title}</h4>
      </div>
      <p className="text-xs leading-relaxed">{description}</p>
    </div>
  )
}

function SecurityBar({ label, value, max, description, isPercent }: {
  label: string
  value: number
  max: number
  description: string
  isPercent?: boolean
}) {
  const pct = (value / max) * 100
  return (
    <div className="bg-[var(--surface-overlay)] rounded-lg p-3 border border-[var(--border-subtle)]">
      <div className="flex justify-between items-center mb-1.5">
        <span className="text-xs font-medium text-[var(--text-primary)]">{label}</span>
        <span className="text-xs font-mono font-semibold text-[var(--text-primary)]">
          {isPercent ? `${value}%` : `${value}/${max}`}
        </span>
      </div>
      <div className="w-full h-2 bg-slate-200 rounded-full overflow-hidden">
        <div
          className={cn(
            'h-full rounded-full transition-all',
            pct >= 70 ? 'bg-green-500' : pct >= 40 ? 'bg-amber-500' : 'bg-red-500'
          )}
          style={{ width: `${pct}%` }}
        />
      </div>
      <div className="text-2xs text-[var(--text-muted)] mt-1">{description}</div>
    </div>
  )
}
