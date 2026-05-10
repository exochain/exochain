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

import { cn } from '../lib/utils'

interface AiRecommendationCardProps {
  recommendation: string
  confidence: number
  modelVersion: string
  proofVerified: boolean
  onHumanReview: () => void
}

/**
 * AI recommendation card with confidence scores and zkML proof (UX-004).
 * Includes mandatory human review gate per TNC-02.
 */
export function AiRecommendationCard({
  recommendation,
  confidence,
  modelVersion,
  proofVerified,
  onHumanReview,
}: AiRecommendationCardProps) {
  const confidencePct = Math.round(confidence * 100)
  const confidenceColor =
    confidence >= 0.8 ? 'text-green-600' : confidence >= 0.5 ? 'text-yellow-600' : 'text-red-600'

  return (
    <div className="border rounded-lg p-4 bg-purple-50 border-purple-200" role="region" aria-label="AI Recommendation">
      <div className="flex items-center gap-2 mb-2">
        <span className="text-xs font-medium text-purple-700 bg-purple-100 px-2 py-0.5 rounded">AI Recommendation</span>
        {proofVerified && (
          <span className="text-xs font-medium text-green-700 bg-green-100 px-2 py-0.5 rounded" aria-label="zkML proof verified">
            Proof Verified
          </span>
        )}
      </div>

      <p className="text-sm text-gray-800 mb-3">{recommendation}</p>

      <div className="flex items-center justify-between text-xs text-gray-500 mb-3">
        <span>
          Confidence: <span className={cn('font-semibold', confidenceColor)}>{confidencePct}%</span>
        </span>
        <span>Model: {modelVersion}</span>
      </div>

      {/* Mandatory human review gate — TNC-02 */}
      <button
        onClick={onHumanReview}
        className="w-full px-4 py-2 bg-governance-600 text-white rounded-md text-sm font-medium hover:bg-governance-700 focus-visible:ring-2 focus-visible:ring-governance-500 focus-visible:ring-offset-2 transition-colors"
        aria-label="Review AI recommendation as a human decision maker"
      >
        Human Review Required
      </button>
      <p className="mt-1 text-xs text-gray-500 text-center">
        TNC-02: AI recommendations require human approval before action
      </p>
    </div>
  )
}
