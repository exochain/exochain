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

import { useState } from 'react';
import { SCENARIO_TYPES } from '@/lib/utils';
import {
  Clock, ChevronRight, CheckCircle, AlertTriangle,
  CloudLightning, Heart, Flame, ShieldAlert, Zap, Bug, Navigation,
} from 'lucide-react';

const ICON_MAP: Record<string, React.ElementType> = {
  CloudLightning, Heart, AlertTriangle, Flame, ShieldAlert, Zap, Bug, Navigation,
};

interface GoldenHourProtocol {
  scenarioId: string;
  steps: Array<{ text: string; timeframe: string; critical: boolean }>;
}

const DEFAULT_PROTOCOLS: Record<string, Array<{ text: string; timeframe: string; critical: boolean }>> = {
  'natural-disaster': [
    { text: 'Drop, Cover, Hold On (earthquake) / Shelter in place (tornado)', timeframe: '0-2 min', critical: true },
    { text: 'Check yourself and immediate family for injuries', timeframe: '2-5 min', critical: true },
    { text: 'Activate PACE communication chain — contact Primary', timeframe: '5-10 min', critical: true },
    { text: 'Shut off gas, water, electricity if damage detected', timeframe: '10-15 min', critical: false },
    { text: 'Grab go-bag if evacuating, or shelter in safe room', timeframe: '15-20 min', critical: false },
    { text: 'Move to rally point if building is unsafe', timeframe: '20-30 min', critical: false },
    { text: 'Check on neighbors, especially elderly and disabled', timeframe: '30-45 min', critical: false },
    { text: 'Monitor emergency broadcasts (radio/NOAA)', timeframe: '45-60 min', critical: false },
  ],
  'medical': [
    { text: 'Call 911 / local emergency number immediately', timeframe: '0-1 min', critical: true },
    { text: 'Begin CPR or stop severe bleeding', timeframe: '1-3 min', critical: true },
    { text: 'Share ICE card QR with first responders', timeframe: '3-5 min', critical: true },
    { text: 'Contact Primary PACE trustee', timeframe: '5-10 min', critical: true },
    { text: 'Gather medications list and insurance info', timeframe: '10-15 min', critical: false },
    { text: 'Secure pets and home if leaving for hospital', timeframe: '15-30 min', critical: false },
    { text: 'Notify remaining PACE trustees', timeframe: '30-45 min', critical: false },
    { text: 'Document incident details while fresh', timeframe: '45-60 min', critical: false },
  ],
  'civil-unrest': [
    { text: 'Assess immediate danger — stay or move?', timeframe: '0-2 min', critical: true },
    { text: 'Move away from crowds, get to solid cover', timeframe: '2-5 min', critical: true },
    { text: 'Contact Primary PACE trustee — share location', timeframe: '5-10 min', critical: true },
    { text: 'Avoid documenting on phone if it draws attention', timeframe: '10-15 min', critical: false },
    { text: 'Identify multiple exit routes from current location', timeframe: '15-20 min', critical: false },
    { text: 'Monitor situation via radio (conserve phone battery)', timeframe: '20-30 min', critical: false },
    { text: 'If curfew declared, shelter in place immediately', timeframe: '30-45 min', critical: true },
    { text: 'Document injuries, property damage for insurance', timeframe: '45-60 min', critical: false },
  ],
};

export default function GoldenHour() {
  const [selectedScenario, setSelectedScenario] = useState<string | null>(null);
  const [completedSteps, setCompletedSteps] = useState<Set<number>>(new Set());

  const toggleStep = (index: number) => {
    setCompletedSteps(prev => {
      const next = new Set(prev);
      if (next.has(index)) next.delete(index);
      else next.add(index);
      return next;
    });
  };

  const steps = selectedScenario ? (DEFAULT_PROTOCOLS[selectedScenario] || []) : [];

  return (
    <div className="p-8">
      <div className="mb-8">
        <h2 className="text-2xl font-heading font-bold text-white">Golden Hour Protocols</h2>
        <p className="text-sm text-white/40 mt-1">
          The first 60 minutes matter most. Step-by-step response for every scenario.
        </p>
      </div>

      {/* Explainer */}
      <div className="bg-amber-500/5 border border-amber-400/20 rounded-xl p-5 mb-8">
        <div className="flex items-start gap-3">
          <Clock size={18} className="text-amber-400 mt-0.5 shrink-0" />
          <div>
            <p className="text-sm text-white font-medium mb-1">What is the Golden Hour?</p>
            <p className="text-xs text-white/40 leading-relaxed">
              In emergency medicine, the "Golden Hour" is the critical first 60 minutes after
              a traumatic event where rapid response dramatically improves outcomes. We've adapted
              this concept for civil defense — your first hour actions in any emergency scenario
              determine your safety trajectory.
            </p>
          </div>
        </div>
      </div>

      {!selectedScenario ? (
        /* Scenario Selector */
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {SCENARIO_TYPES.filter(s => DEFAULT_PROTOCOLS[s.id]).map(scenario => {
            const Icon = ICON_MAP[scenario.icon] || Clock;
            return (
              <button
                key={scenario.id}
                onClick={() => { setSelectedScenario(scenario.id); setCompletedSteps(new Set()); }}
                className="p-5 bg-white/[0.02] border border-white/10 rounded-xl text-left hover:border-blue-400/30 transition-all group"
              >
                <Icon size={20} className="text-white/30 group-hover:text-blue-400 mb-3 transition-colors" />
                <p className="text-sm font-medium text-white mb-1">{scenario.label}</p>
                <p className="text-[11px] text-white/30">{DEFAULT_PROTOCOLS[scenario.id]?.length || 0} steps</p>
                <div className="flex items-center gap-1 mt-3 text-[10px] text-blue-300/50">
                  Start Protocol <ChevronRight size={10} />
                </div>
              </button>
            );
          })}
        </div>
      ) : (
        /* Active Protocol */
        <div className="max-w-2xl">
          <button
            onClick={() => setSelectedScenario(null)}
            className="text-xs text-blue-300/50 hover:text-blue-300 mb-4 flex items-center gap-1"
          >
            &larr; Back to scenarios
          </button>

          <div className="flex items-center gap-3 mb-6">
            <Clock size={20} className="text-amber-400" />
            <h3 className="text-lg font-heading font-semibold text-white">
              {SCENARIO_TYPES.find(s => s.id === selectedScenario)?.label} — 60 Minute Protocol
            </h3>
          </div>

          {/* Progress */}
          <div className="flex items-center gap-2 mb-6">
            <div className="flex-1 h-2 bg-white/5 rounded-full overflow-hidden">
              <div
                className="h-full bg-blue-400 rounded-full transition-all"
                style={{ width: `${steps.length ? (completedSteps.size / steps.length) * 100 : 0}%` }}
              />
            </div>
            <span className="text-xs text-white/40 font-mono">
              {completedSteps.size}/{steps.length}
            </span>
          </div>

          {/* Steps */}
          <div className="space-y-3">
            {steps.map((step, i) => (
              <button
                key={i}
                onClick={() => toggleStep(i)}
                className={`w-full text-left p-4 rounded-xl border transition-all flex items-start gap-3 ${
                  completedSteps.has(i)
                    ? 'bg-blue-500/5 border-blue-400/20'
                    : step.critical
                      ? 'bg-red-500/5 border-red-400/20'
                      : 'bg-white/[0.02] border-white/10 hover:border-white/20'
                }`}
              >
                <div className="mt-0.5 shrink-0">
                  {completedSteps.has(i) ? (
                    <CheckCircle size={18} className="text-blue-400" />
                  ) : step.critical ? (
                    <AlertTriangle size={18} className="text-red-400" />
                  ) : (
                    <div className="w-[18px] h-[18px] rounded-full border-2 border-white/20" />
                  )}
                </div>
                <div className="flex-1">
                  <p className={`text-sm ${completedSteps.has(i) ? 'text-white/40 line-through' : 'text-white'}`}>
                    {step.text}
                  </p>
                  <div className="flex items-center gap-2 mt-1">
                    <span className="text-[10px] text-white/30 font-mono">{step.timeframe}</span>
                    {step.critical && !completedSteps.has(i) && (
                      <span className="text-[10px] text-red-400 font-medium">CRITICAL</span>
                    )}
                  </div>
                </div>
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
