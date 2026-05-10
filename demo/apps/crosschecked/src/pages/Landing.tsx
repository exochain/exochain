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

import { Link } from 'react-router-dom';
import {
  ShieldCheck,
  Users,
  Fingerprint,
  Link as LinkIcon,
  ScrollText,
  Grid3X3,
  ArrowRight,
} from 'lucide-react';

const features = [
  {
    icon: Users,
    title: '5-Panel Council',
    description:
      'Governance, Legal, Architecture, Security, and Operations panels each evaluate proposals independently before synthesis.',
  },
  {
    icon: Fingerprint,
    title: 'Anti-Sybil Verification',
    description:
      'Independence analysis detects coordinated or duplicated opinions across agents, ensuring genuine plurality.',
  },
  {
    icon: LinkIcon,
    title: 'Hash-Chained Receipts',
    description:
      'Every action is hash-chained into an immutable custody log with cryptographic signatures and on-chain anchors.',
  },
  {
    icon: ScrollText,
    title: 'Constitutional Governance',
    description:
      'Decision classes from Operational to Constitutional ensure proportional review depth and quorum requirements.',
  },
  {
    icon: Grid3X3,
    title: '5x5 Treatment',
    description:
      'Full matrix analysis: 5 panels x 5 digital-rights properties (Storable, Diffable, Transferable, Auditable, Contestable).',
  },
];

export default function Landing() {
  return (
    <div className="min-h-screen bg-xc-navy">
      {/* Nav */}
      <header className="border-b border-white/5">
        <div className="max-w-6xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-xc-indigo-500 to-xc-purple-500 flex items-center justify-center">
              <ShieldCheck className="w-5 h-5 text-white" />
            </div>
            <span className="font-heading font-bold text-white text-lg">
              CrossChecked<span className="text-xc-indigo-400">.ai</span>
            </span>
          </div>
          <Link
            to="/login"
            className="text-sm font-medium text-gray-400 hover:text-white transition-colors"
          >
            Sign In
          </Link>
        </div>
      </header>

      {/* Hero */}
      <section className="max-w-4xl mx-auto px-6 pt-24 pb-16 text-center">
        <h1 className="font-heading font-extrabold text-5xl md:text-6xl leading-tight">
          <span className="bg-gradient-to-r from-xc-indigo-400 to-xc-purple-400 bg-clip-text text-transparent">
            Plural Intelligence
          </span>
          <br />
          <span className="text-white">for Every Decision</span>
        </h1>
        <p className="mt-6 text-lg text-gray-400 max-w-2xl mx-auto leading-relaxed">
          A 5-panel AI-IRB council crosschecks every proposal through independent agents,
          anti-Sybil verification, and hash-chained custody -- so decisions are trustworthy
          before they become irreversible.
        </p>
        <div className="mt-10 flex items-center justify-center gap-4 flex-wrap">
          <Link
            to="/register"
            className="inline-flex items-center gap-2 px-6 py-3 rounded-lg bg-gradient-to-r from-xc-indigo-500 to-xc-purple-500 text-white font-medium text-sm hover:shadow-lg hover:shadow-xc-indigo-500/25 transition-all"
          >
            Submit a Proposal
            <ArrowRight className="w-4 h-4" />
          </Link>
          <Link
            to="/login"
            className="inline-flex items-center gap-2 px-6 py-3 rounded-lg border border-white/10 text-gray-300 font-medium text-sm hover:border-white/20 hover:text-white transition-all"
          >
            Sign In
          </Link>
        </div>
      </section>

      {/* Features */}
      <section className="max-w-6xl mx-auto px-6 py-16">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {features.map((f) => (
            <div
              key={f.title}
              className="rounded-xl border border-white/5 bg-xc-slate/40 p-6 hover:border-xc-indigo-500/20 transition-colors"
            >
              <div className="w-10 h-10 rounded-lg bg-xc-indigo-500/10 flex items-center justify-center mb-4">
                <f.icon className="w-5 h-5 text-xc-indigo-400" />
              </div>
              <h3 className="font-heading font-semibold text-white mb-2">{f.title}</h3>
              <p className="text-sm text-gray-400 leading-relaxed">{f.description}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-white/5 py-8">
        <div className="max-w-6xl mx-auto px-6 flex items-center justify-between">
          <p className="text-xs text-gray-500">
            Powered by{' '}
            <span className="font-medium text-gray-400">EXOCHAIN</span> Trust Fabric
          </p>
          <p className="text-xs text-gray-500">CrossChecked.ai v0.1.0</p>
        </div>
      </footer>
    </div>
  );
}
