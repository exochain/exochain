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
import { useAuth } from '@/hooks/useAuth';
import { SCENARIO_TYPES } from '@/lib/utils';
import {
  FileText, Plus, X, CloudLightning, Heart, AlertTriangle,
  Flame, ShieldAlert, Zap, Bug, Navigation, ChevronRight,
  MapPin, Package, Phone, Route,
} from 'lucide-react';

const ICON_MAP: Record<string, React.ElementType> = {
  CloudLightning, Heart, AlertTriangle, Flame, ShieldAlert, Zap, Bug, Navigation,
};

interface PlanDraft {
  scenario_type: string;
  name: string;
  rally_point: string;
  communication_plan: string;
  evacuation_routes: string;
  special_instructions: string;
  go_bag_items: string;
  golden_hour_steps: string;
}

const EMPTY_PLAN: PlanDraft = {
  scenario_type: '', name: '', rally_point: '', communication_plan: '',
  evacuation_routes: '', special_instructions: '', go_bag_items: '', golden_hour_steps: '',
};

export default function EmergencyPlans() {
  const { auth } = useAuth();
  const [plans, setPlans] = useState<Array<PlanDraft & { id: string }>>([]);
  const [showCreate, setShowCreate] = useState(false);
  const [selectedScenario, setSelectedScenario] = useState<string | null>(null);
  const [draft, setDraft] = useState<PlanDraft>(EMPTY_PLAN);

  const startPlan = (scenarioId: string) => {
    const scenario = SCENARIO_TYPES.find(s => s.id === scenarioId);
    setDraft({ ...EMPTY_PLAN, scenario_type: scenarioId, name: `${scenario?.label || ''} Response Plan` });
    setSelectedScenario(scenarioId);
    setShowCreate(true);
  };

  const savePlan = () => {
    setPlans(prev => [...prev, { ...draft, id: crypto.randomUUID() }]);
    setShowCreate(false);
    setSelectedScenario(null);
    setDraft(EMPTY_PLAN);
  };

  return (
    <div className="p-8">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h2 className="text-2xl font-heading font-bold text-white">Emergency Plans</h2>
          <p className="text-sm text-white/40 mt-1">
            Prepare response protocols for every scenario
          </p>
        </div>
      </div>

      {/* Scenario Grid */}
      {!showCreate && (
        <>
          <h3 className="text-sm font-heading font-semibold text-white/60 mb-4 uppercase tracking-wider">
            Create a plan for...
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-10">
            {SCENARIO_TYPES.map(scenario => {
              const Icon = ICON_MAP[scenario.icon] || FileText;
              const hasPlan = plans.some(p => p.scenario_type === scenario.id);
              return (
                <button
                  key={scenario.id}
                  onClick={() => startPlan(scenario.id)}
                  className={`p-5 rounded-xl border text-left transition-all group ${
                    hasPlan
                      ? 'bg-blue-500/5 border-blue-400/30'
                      : 'bg-white/[0.02] border-white/10 hover:border-blue-400/30'
                  }`}
                >
                  <Icon size={20} className={hasPlan ? 'text-blue-400 mb-3' : 'text-white/30 mb-3 group-hover:text-blue-400'} />
                  <p className="text-sm font-medium text-white mb-1">{scenario.label}</p>
                  <p className="text-[11px] text-white/30">{scenario.description}</p>
                  {hasPlan && (
                    <span className="text-[10px] text-blue-400 mt-2 flex items-center gap-1">
                      Plan created <ChevronRight size={10} />
                    </span>
                  )}
                </button>
              );
            })}
          </div>

          {/* Existing Plans */}
          {plans.length > 0 && (
            <>
              <h3 className="text-sm font-heading font-semibold text-white/60 mb-4 uppercase tracking-wider">
                Your Plans ({plans.length})
              </h3>
              <div className="space-y-3">
                {plans.map(plan => {
                  const scenario = SCENARIO_TYPES.find(s => s.id === plan.scenario_type);
                  const Icon = ICON_MAP[scenario?.icon || ''] || FileText;
                  return (
                    <div key={plan.id} className="bg-white/[0.03] border border-white/10 rounded-xl p-5">
                      <div className="flex items-center gap-3">
                        <Icon size={18} className="text-blue-400" />
                        <div>
                          <p className="text-sm font-medium text-white">{plan.name}</p>
                          <p className="text-[11px] text-white/30">{scenario?.label}</p>
                        </div>
                      </div>
                      {plan.rally_point && (
                        <div className="flex items-center gap-2 mt-3 text-xs text-white/40">
                          <MapPin size={12} /> Rally Point: {plan.rally_point}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </>
          )}
        </>
      )}

      {/* Create Plan Form */}
      {showCreate && (
        <div className="max-w-2xl">
          <div className="flex items-center justify-between mb-6">
            <h3 className="text-lg font-heading font-semibold text-white">{draft.name}</h3>
            <button onClick={() => { setShowCreate(false); setSelectedScenario(null); }}>
              <X size={18} className="text-white/30" />
            </button>
          </div>

          <div className="space-y-6">
            <div>
              <label className="flex items-center gap-2 text-xs text-white/50 mb-2">
                <MapPin size={12} /> Rally Point
              </label>
              <input
                type="text"
                placeholder="Where does your family meet if separated?"
                value={draft.rally_point}
                onChange={(e) => setDraft({ ...draft, rally_point: e.target.value })}
                className="w-full bg-white/5 border border-white/10 rounded-lg px-4 py-3 text-sm text-white focus:outline-none focus:border-blue-400 placeholder-white/20"
              />
            </div>

            <div>
              <label className="flex items-center gap-2 text-xs text-white/50 mb-2">
                <Phone size={12} /> Communication Plan
              </label>
              <textarea
                placeholder="How will you contact each other? Out-of-area contact? Radio frequencies?"
                value={draft.communication_plan}
                onChange={(e) => setDraft({ ...draft, communication_plan: e.target.value })}
                rows={3}
                className="w-full bg-white/5 border border-white/10 rounded-lg px-4 py-3 text-sm text-white focus:outline-none focus:border-blue-400 placeholder-white/20 resize-none"
              />
            </div>

            <div>
              <label className="flex items-center gap-2 text-xs text-white/50 mb-2">
                <Route size={12} /> Evacuation Routes
              </label>
              <textarea
                placeholder="Primary and secondary evacuation routes (one per line)"
                value={draft.evacuation_routes}
                onChange={(e) => setDraft({ ...draft, evacuation_routes: e.target.value })}
                rows={3}
                className="w-full bg-white/5 border border-white/10 rounded-lg px-4 py-3 text-sm text-white focus:outline-none focus:border-blue-400 placeholder-white/20 resize-none"
              />
            </div>

            <div>
              <label className="flex items-center gap-2 text-xs text-white/50 mb-2">
                <Package size={12} /> Go-Bag Checklist
              </label>
              <textarea
                placeholder="Essential items to grab (one per line): Water, First Aid Kit, Documents, Radio..."
                value={draft.go_bag_items}
                onChange={(e) => setDraft({ ...draft, go_bag_items: e.target.value })}
                rows={4}
                className="w-full bg-white/5 border border-white/10 rounded-lg px-4 py-3 text-sm text-white focus:outline-none focus:border-blue-400 placeholder-white/20 resize-none font-mono text-xs"
              />
            </div>

            <div>
              <label className="flex items-center gap-2 text-xs text-white/50 mb-2">
                <FileText size={12} /> Golden Hour Steps
              </label>
              <textarea
                placeholder="First 60 minutes — step-by-step actions (one per line)"
                value={draft.golden_hour_steps}
                onChange={(e) => setDraft({ ...draft, golden_hour_steps: e.target.value })}
                rows={4}
                className="w-full bg-white/5 border border-white/10 rounded-lg px-4 py-3 text-sm text-white focus:outline-none focus:border-blue-400 placeholder-white/20 resize-none font-mono text-xs"
              />
            </div>

            <div>
              <label className="text-xs text-white/50 mb-2 block">Special Instructions</label>
              <textarea
                placeholder="Pets, medications, elderly family members, accessibility needs..."
                value={draft.special_instructions}
                onChange={(e) => setDraft({ ...draft, special_instructions: e.target.value })}
                rows={3}
                className="w-full bg-white/5 border border-white/10 rounded-lg px-4 py-3 text-sm text-white focus:outline-none focus:border-blue-400 placeholder-white/20 resize-none"
              />
            </div>

            <button
              onClick={savePlan}
              className="w-full bg-blue-500 hover:bg-blue-600 text-white font-semibold py-4 rounded-xl transition-colors flex items-center justify-center gap-2"
            >
              <Plus size={16} />
              Save Emergency Plan
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
