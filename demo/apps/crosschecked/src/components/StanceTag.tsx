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

import { cn } from '@/lib/utils';
import { STANCE_COLORS } from '@/lib/utils';

interface StanceTagProps {
  stance: string;
  size?: 'sm' | 'md';
  className?: string;
}

export default function StanceTag({ stance, size = 'md', className }: StanceTagProps) {
  return (
    <span
      className={cn(
        'inline-flex items-center rounded-md border font-medium capitalize',
        size === 'sm' ? 'px-1.5 py-0.5 text-[10px]' : 'px-2.5 py-1 text-xs',
        STANCE_COLORS[stance] || 'bg-gray-500/20 text-gray-400 border-gray-400/30',
        className,
      )}
    >
      {stance}
    </span>
  );
}
