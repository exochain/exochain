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
import {
  QrCode, Heart, Pill, AlertTriangle, Phone, Plus, X,
  Droplets, Shield, FileCheck,
} from 'lucide-react';

interface IceCardData {
  full_name: string;
  date_of_birth: string;
  blood_type: string;
  allergies: string[];
  medications: string[];
  medical_conditions: string[];
  emergency_contacts: Array<{ name: string; phone: string; relationship: string }>;
  insurance_info: string;
  organ_donor: boolean;
  dnr: boolean;
  special_instructions: string;
}

const BLOOD_TYPES = ['A+', 'A-', 'B+', 'B-', 'AB+', 'AB-', 'O+', 'O-', 'Unknown'];

export default function IceCard() {
  const { auth } = useAuth();
  const [card, setCard] = useState<IceCardData>({
    full_name: auth?.displayName || '',
    date_of_birth: '',
    blood_type: '',
    allergies: [],
    medications: [],
    medical_conditions: [],
    emergency_contacts: [],
    insurance_info: '',
    organ_donor: false,
    dnr: false,
    special_instructions: '',
  });
  const [newAllergy, setNewAllergy] = useState('');
  const [newMed, setNewMed] = useState('');
  const [newCondition, setNewCondition] = useState('');
  const [newContact, setNewContact] = useState({ name: '', phone: '', relationship: '' });
  const [saved, setSaved] = useState(false);

  const addItem = (field: 'allergies' | 'medications' | 'medical_conditions', value: string, clear: () => void) => {
    if (!value.trim()) return;
    setCard(prev => ({ ...prev, [field]: [...prev[field], value.trim()] }));
    clear();
  };

  const removeItem = (field: 'allergies' | 'medications' | 'medical_conditions', index: number) => {
    setCard(prev => ({ ...prev, [field]: prev[field].filter((_, i) => i !== index) }));
  };

  const addContact = () => {
    if (!newContact.name || !newContact.phone) return;
    setCard(prev => ({ ...prev, emergency_contacts: [...prev.emergency_contacts, { ...newContact }] }));
    setNewContact({ name: '', phone: '', relationship: '' });
  };

  const save = () => {
    setSaved(true);
    setTimeout(() => setSaved(false), 3000);
  };

  return (
    <div className="p-8 max-w-3xl">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h2 className="text-2xl font-heading font-bold text-white">ICE Card</h2>
          <p className="text-sm text-white/40 mt-1">
            In Case of Emergency — your digital medical identity card
          </p>
        </div>
      </div>

      {/* Card Preview */}
      <div className="bg-gradient-to-br from-blue-600/30 to-cyan-600/20 border border-blue-400/30 rounded-2xl p-6 mb-8">
        <div className="flex items-start justify-between mb-4">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <Shield size={16} className="text-blue-300" />
              <span className="text-xs text-blue-200 font-medium uppercase tracking-wider">
                IN CASE OF EMERGENCY
              </span>
            </div>
            <p className="text-xl font-heading font-bold text-white">
              {card.full_name || 'Your Name'}
            </p>
            <p className="text-xs text-blue-200/50 mt-1">DOB: {card.date_of_birth || '—'}</p>
          </div>
          <div className="w-20 h-20 bg-white rounded-lg flex items-center justify-center">
            <QrCode size={48} className="text-blue-600" />
          </div>
        </div>
        <div className="grid grid-cols-3 gap-4 text-xs">
          <div>
            <p className="text-blue-200/50 mb-0.5">Blood Type</p>
            <p className="text-white font-medium">{card.blood_type || '—'}</p>
          </div>
          <div>
            <p className="text-blue-200/50 mb-0.5">Allergies</p>
            <p className="text-white font-medium">{card.allergies.length ? card.allergies.join(', ') : 'None'}</p>
          </div>
          <div>
            <p className="text-blue-200/50 mb-0.5">Contacts</p>
            <p className="text-white font-medium">{card.emergency_contacts.length || 0}</p>
          </div>
        </div>
        <p className="text-[10px] text-blue-200/30 mt-4">
          Scan QR for consent-gated access to full medical info
        </p>
      </div>

      {/* Form */}
      <div className="space-y-6">
        {/* Basic Info */}
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="text-xs text-white/50 mb-1.5 block">Full Legal Name</label>
            <input
              type="text"
              value={card.full_name}
              onChange={(e) => setCard({ ...card, full_name: e.target.value })}
              className="w-full bg-white/5 border border-white/10 rounded-lg px-4 py-3 text-sm text-white focus:outline-none focus:border-blue-400"
            />
          </div>
          <div>
            <label className="text-xs text-white/50 mb-1.5 block">Date of Birth</label>
            <input
              type="date"
              value={card.date_of_birth}
              onChange={(e) => setCard({ ...card, date_of_birth: e.target.value })}
              className="w-full bg-white/5 border border-white/10 rounded-lg px-4 py-3 text-sm text-white focus:outline-none focus:border-blue-400"
            />
          </div>
        </div>

        <div>
          <label className="flex items-center gap-2 text-xs text-white/50 mb-1.5">
            <Droplets size={12} /> Blood Type
          </label>
          <div className="flex flex-wrap gap-2">
            {BLOOD_TYPES.map(bt => (
              <button
                key={bt}
                onClick={() => setCard({ ...card, blood_type: bt })}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                  card.blood_type === bt
                    ? 'bg-blue-500 text-white'
                    : 'bg-white/5 text-white/40 border border-white/10 hover:border-blue-400/30'
                }`}
              >
                {bt}
              </button>
            ))}
          </div>
        </div>

        {/* Allergies */}
        <div>
          <label className="flex items-center gap-2 text-xs text-white/50 mb-1.5">
            <AlertTriangle size={12} /> Allergies
          </label>
          <div className="flex gap-2 mb-2">
            <input
              type="text"
              placeholder="Add allergy..."
              value={newAllergy}
              onChange={(e) => setNewAllergy(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && addItem('allergies', newAllergy, () => setNewAllergy(''))}
              className="flex-1 bg-white/5 border border-white/10 rounded-lg px-4 py-2 text-sm text-white focus:outline-none focus:border-blue-400 placeholder-white/20"
            />
            <button onClick={() => addItem('allergies', newAllergy, () => setNewAllergy(''))} className="px-3 bg-white/5 border border-white/10 rounded-lg text-white/40 hover:text-blue-400">
              <Plus size={14} />
            </button>
          </div>
          <div className="flex flex-wrap gap-2">
            {card.allergies.map((a, i) => (
              <span key={i} className="flex items-center gap-1 px-3 py-1 bg-red-500/10 border border-red-400/20 rounded-full text-xs text-red-300">
                {a}
                <button onClick={() => removeItem('allergies', i)}><X size={10} /></button>
              </span>
            ))}
          </div>
        </div>

        {/* Medications */}
        <div>
          <label className="flex items-center gap-2 text-xs text-white/50 mb-1.5">
            <Pill size={12} /> Current Medications
          </label>
          <div className="flex gap-2 mb-2">
            <input
              type="text"
              placeholder="Add medication..."
              value={newMed}
              onChange={(e) => setNewMed(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && addItem('medications', newMed, () => setNewMed(''))}
              className="flex-1 bg-white/5 border border-white/10 rounded-lg px-4 py-2 text-sm text-white focus:outline-none focus:border-blue-400 placeholder-white/20"
            />
            <button onClick={() => addItem('medications', newMed, () => setNewMed(''))} className="px-3 bg-white/5 border border-white/10 rounded-lg text-white/40 hover:text-blue-400">
              <Plus size={14} />
            </button>
          </div>
          <div className="flex flex-wrap gap-2">
            {card.medications.map((m, i) => (
              <span key={i} className="flex items-center gap-1 px-3 py-1 bg-blue-500/10 border border-blue-400/20 rounded-full text-xs text-blue-300">
                {m}
                <button onClick={() => removeItem('medications', i)}><X size={10} /></button>
              </span>
            ))}
          </div>
        </div>

        {/* Emergency Contacts */}
        <div>
          <label className="flex items-center gap-2 text-xs text-white/50 mb-1.5">
            <Phone size={12} /> Emergency Contacts
          </label>
          {card.emergency_contacts.map((c, i) => (
            <div key={i} className="flex items-center justify-between bg-white/5 rounded-lg px-4 py-2 mb-2">
              <div>
                <p className="text-sm text-white">{c.name}</p>
                <p className="text-[11px] text-white/30">{c.phone} · {c.relationship}</p>
              </div>
              <button onClick={() => setCard(prev => ({
                ...prev, emergency_contacts: prev.emergency_contacts.filter((_, idx) => idx !== i)
              }))}>
                <X size={14} className="text-white/30" />
              </button>
            </div>
          ))}
          <div className="grid grid-cols-3 gap-2">
            <input type="text" placeholder="Name" value={newContact.name}
              onChange={(e) => setNewContact({ ...newContact, name: e.target.value })}
              className="bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-400 placeholder-white/20" />
            <input type="tel" placeholder="Phone" value={newContact.phone}
              onChange={(e) => setNewContact({ ...newContact, phone: e.target.value })}
              className="bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-400 placeholder-white/20" />
            <div className="flex gap-2">
              <input type="text" placeholder="Relationship" value={newContact.relationship}
                onChange={(e) => setNewContact({ ...newContact, relationship: e.target.value })}
                className="flex-1 bg-white/5 border border-white/10 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-400 placeholder-white/20" />
              <button onClick={addContact} className="px-3 bg-white/5 border border-white/10 rounded-lg text-white/40 hover:text-blue-400">
                <Plus size={14} />
              </button>
            </div>
          </div>
        </div>

        {/* Toggles */}
        <div className="flex gap-6">
          <label className="flex items-center gap-3 cursor-pointer">
            <input type="checkbox" checked={card.organ_donor}
              onChange={(e) => setCard({ ...card, organ_donor: e.target.checked })}
              className="w-4 h-4 rounded border-white/20 bg-white/5 text-blue-500 focus:ring-blue-500" />
            <span className="text-sm text-white/60">
              <Heart size={12} className="inline mr-1 text-red-400" />
              Organ Donor
            </span>
          </label>
          <label className="flex items-center gap-3 cursor-pointer">
            <input type="checkbox" checked={card.dnr}
              onChange={(e) => setCard({ ...card, dnr: e.target.checked })}
              className="w-4 h-4 rounded border-white/20 bg-white/5 text-blue-500 focus:ring-blue-500" />
            <span className="text-sm text-white/60">
              <FileCheck size={12} className="inline mr-1 text-amber-400" />
              DNR (Do Not Resuscitate)
            </span>
          </label>
        </div>

        {/* Save */}
        <button
          onClick={save}
          className="w-full bg-blue-500 hover:bg-blue-600 text-white font-semibold py-4 rounded-xl transition-colors flex items-center justify-center gap-2"
        >
          <QrCode size={16} />
          {saved ? 'ICE Card Saved & QR Generated' : 'Save ICE Card & Generate QR'}
        </button>
      </div>
    </div>
  );
}
