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

import { useNavigate } from 'react-router-dom';
import {
  Shield, Users, Heart, Zap, ChevronRight, Clock,
  CloudLightning, AlertTriangle, Navigation, QrCode,
} from 'lucide-react';

const FEATURES = [
  {
    icon: Shield,
    title: 'Emergency Plans',
    description: 'Custom response protocols for every scenario — natural disasters, civil unrest, active threats, infrastructure failure.',
  },
  {
    icon: QrCode,
    title: 'Digital ICE Cards',
    description: 'QR/NFC emergency cards with consent-gated access to your medical info. First responders scan, you stay in control.',
  },
  {
    icon: Users,
    title: 'PACE Trustee Network',
    description: 'Name 4 trusted contacts — Primary, Alternate, Contingency, Emergency. Key shards protect your digital legacy.',
  },
  {
    icon: Clock,
    title: 'Golden Hour Protocols',
    description: 'The first 60 minutes matter most. Step-by-step checklists activated the moment an emergency strikes.',
  },
];

const SCENARIOS = [
  { icon: CloudLightning, label: 'Natural Disaster', color: 'text-blue-400' },
  { icon: Heart, label: 'Medical Emergency', color: 'text-red-400' },
  { icon: AlertTriangle, label: 'Civil Unrest', color: 'text-amber-400' },
  { icon: Zap, label: 'Infrastructure Failure', color: 'text-cyan-400' },
  { icon: Navigation, label: 'Evacuation', color: 'text-teal-400' },
];

export default function Landing() {
  const navigate = useNavigate();

  return (
    <div className="min-h-screen bg-gradient-to-b from-[#0a1628] via-[#0f1d32] to-[#0a1628]">
      {/* Header */}
      <header className="flex items-center justify-between px-8 py-5 max-w-7xl mx-auto">
        <div className="flex items-center gap-2">
          <Shield className="text-blue-400" size={28} />
          <span className="text-xl font-heading font-bold text-white">
            Live<span className="text-blue-400">Safe</span><span className="text-blue-400/60">.ai</span>
          </span>
        </div>
        <div className="flex items-center gap-4">
          <button
            onClick={() => navigate('/login')}
            className="text-sm text-blue-200 hover:text-white transition-colors"
          >
            Sign In
          </button>
          <button
            onClick={() => navigate('/register')}
            className="px-5 py-2 bg-blue-500 hover:bg-blue-600 text-white font-medium rounded-lg text-sm transition-colors"
          >
            Get Started
          </button>
        </div>
      </header>

      {/* Hero */}
      <section className="max-w-4xl mx-auto px-8 pt-20 pb-16 text-center">
        <div className="inline-flex items-center gap-2 px-4 py-1.5 bg-blue-500/10 border border-blue-500/20 rounded-full mb-8">
          <Shield size={14} className="text-blue-400" />
          <span className="text-xs text-blue-300 font-medium">Modern Civil Defense Preparedness</span>
        </div>

        <h1 className="text-5xl md:text-7xl font-heading font-extrabold text-white leading-tight mb-6">
          Be Someone's<br />
          <span className="bg-gradient-to-r from-blue-400 via-cyan-400 to-teal-400 bg-clip-text text-transparent">
            Safety Net
          </span>
        </h1>

        <p className="text-lg text-blue-200/70 max-w-2xl mx-auto mb-10 leading-relaxed">
          Emergency preparedness meets golden hour response. Create plans for every
          scenario, build your trusted PACE network, and carry a digital ICE card
          that speaks when you can't.
        </p>

        <div className="flex items-center justify-center gap-4 mb-16">
          <button
            onClick={() => navigate('/register')}
            className="px-8 py-4 bg-blue-500 hover:bg-blue-600 text-white font-semibold rounded-xl text-lg transition-all shadow-lg shadow-blue-500/25 flex items-center gap-2"
          >
            Create Your Safety Net
            <ChevronRight size={18} />
          </button>
          <button
            onClick={() => navigate('/login')}
            className="px-8 py-4 border border-blue-400/30 hover:border-blue-400/60 text-blue-300 font-medium rounded-xl text-lg transition-colors"
          >
            I was invited
          </button>
        </div>

        {/* Scenario Pills */}
        <div className="flex flex-wrap items-center justify-center gap-3">
          {SCENARIOS.map(({ icon: Icon, label, color }) => (
            <div key={label} className="flex items-center gap-2 px-4 py-2 bg-white/5 border border-white/10 rounded-lg">
              <Icon size={14} className={color} />
              <span className="text-xs text-white/60">{label}</span>
            </div>
          ))}
        </div>
      </section>

      {/* Features */}
      <section className="max-w-6xl mx-auto px-8 py-20">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {FEATURES.map(({ icon: Icon, title, description }) => (
            <div
              key={title}
              className="p-8 bg-white/[0.03] border border-white/10 rounded-2xl hover:border-blue-400/30 transition-colors"
            >
              <div className="w-12 h-12 rounded-xl bg-blue-500/10 flex items-center justify-center mb-5">
                <Icon size={22} className="text-blue-400" />
              </div>
              <h3 className="text-lg font-heading font-semibold text-white mb-2">{title}</h3>
              <p className="text-sm text-blue-200/50 leading-relaxed">{description}</p>
            </div>
          ))}
        </div>
      </section>

      {/* PACE Viral Section */}
      <section className="max-w-4xl mx-auto px-8 py-20 text-center">
        <h2 className="text-3xl font-heading font-bold text-white mb-4">
          The 1:4 Safety Network
        </h2>
        <p className="text-blue-200/50 max-w-2xl mx-auto mb-12">
          Every member names 4 PACE trustees. Each trustee holds an encrypted key shard
          and joins the network. One person becomes five. Five become twenty-five.
          Safety scales exponentially.
        </p>

        <div className="grid grid-cols-4 gap-4 max-w-lg mx-auto">
          {['P', 'A', 'C', 'E'].map((letter) => (
            <div
              key={letter}
              className="aspect-square rounded-2xl border-2 border-dashed border-white/20 flex items-center justify-center text-2xl font-heading font-bold text-white/40 hover:border-blue-400/50 hover:text-blue-400 transition-all cursor-default"
            >
              {letter}
            </div>
          ))}
        </div>
        <p className="text-xs text-white/30 mt-6">Primary / Alternate / Contingency / Emergency</p>
      </section>

      {/* Footer */}
      <footer className="border-t border-white/10 py-8 px-8 text-center">
        <div className="flex items-center justify-center gap-2 mb-2">
          <Shield size={16} className="text-blue-400" />
          <span className="text-sm font-heading font-semibold text-white">
            Live<span className="text-blue-400">Safe</span>.ai
          </span>
        </div>
        <p className="text-xs text-white/30">
          Powered by EXOCHAIN Constitutional Trust Fabric
        </p>
        <p className="text-[10px] text-white/20 mt-1">
          Privacy by physics. Preparedness by design.
        </p>
      </footer>
    </div>
  );
}
