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

import * as React from 'react';

export interface Column<T> {
  key: keyof T | string;
  header: React.ReactNode;
  render?: (row: T) => React.ReactNode;
  width?: string;
  align?: 'left' | 'right' | 'center';
}

export function DataTable<T extends { id: string }>({
  columns,
  rows,
  empty
}: {
  columns: Column<T>[];
  rows: T[];
  empty?: React.ReactNode;
}) {
  if (rows.length === 0) {
    return (
      <div className="border border-dashed border-ink/15 dark:border-vellum-soft/10 rounded-md p-8 text-center text-sm text-ink/60 dark:text-vellum-soft/60">
        {empty ?? 'No records to show.'}
      </div>
    );
  }
  return (
    <div className="border border-ink/10 dark:border-vellum-soft/10 rounded-md overflow-x-auto">
      <table className="w-full text-sm">
        <thead className="bg-ink/[0.025] dark:bg-vellum-soft/[0.04]">
          <tr>
            {columns.map((c, i) => (
              <th
                key={i}
                style={{ width: c.width }}
                className={`text-eyebrow text-ink/50 dark:text-vellum-soft/50 px-4 py-3 font-medium text-${c.align ?? 'left'}`}
              >
                {c.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr
              key={row.id}
              className="border-t border-ink/5 dark:border-vellum-soft/5"
            >
              {columns.map((c, i) => (
                <td
                  key={i}
                  className={`px-4 py-3 text-${c.align ?? 'left'} align-top`}
                >
                  {c.render
                    ? c.render(row)
                    : (row as unknown as Record<string, React.ReactNode>)[
                        c.key as string
                      ]}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
