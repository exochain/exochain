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

import { IntPageHead } from '@/components/content/IntPageHead';
import { DataTable, type Column } from '@/components/ui/DataTable';
import { Pill } from '@/components/ui/Pill';
import { ROLE_LABEL } from '@/lib/roles';

export const metadata = { title: 'Users / Orgs' };

interface Row {
  id: string;
  email: string;
  role: keyof typeof ROLE_LABEL;
  org: string;
  status: 'active' | 'suspended';
  createdAt: string;
}

const ROWS: Row[] = [
  { id: 'u_001', email: 'mara@aperture.example', role: 'org_admin', org: 'Aperture Holdings', status: 'active', createdAt: '2026-02-04' },
  { id: 'u_002', email: 'dev@aperture.example', role: 'developer', org: 'Aperture Holdings', status: 'active', createdAt: '2026-02-04' },
  { id: 'u_003', email: 'auditor@auditfirm.example', role: 'auditor', org: 'AuditFirm LLP', status: 'active', createdAt: '2026-04-01' },
  { id: 'u_004', email: 'val@northwind.example', role: 'validator_operator', org: 'Northwind', status: 'active', createdAt: '2026-04-12' }
];

const cols: Column<Row>[] = [
  { key: 'id', header: 'User', render: (r) => <span className="font-mono text-xs">{r.id}</span> },
  { key: 'email', header: 'Email' },
  { key: 'role', header: 'Role', render: (r) => <Pill tone="custody">{ROLE_LABEL[r.role]}</Pill> },
  { key: 'org', header: 'Org' },
  { key: 'status', header: 'Status', render: (r) => r.status === 'active' ? <Pill tone="verify">active</Pill> : <Pill tone="alert">suspended</Pill> },
  { key: 'createdAt', header: 'Joined', render: (r) => <span className="font-mono text-xs">{r.createdAt}</span> }
];

export default function Page() {
  return (
    <>
      <IntPageHead
        eyebrow="Intranet · users"
        title="User and org management"
        lede="Provisioning, deprovisioning, role assignment."
      />
      <DataTable columns={cols} rows={ROWS} />
    </>
  );
}
