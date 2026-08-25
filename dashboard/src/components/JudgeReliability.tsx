import type { JudgeSummary } from '@/types'

/**
 * Fiabilité de la chaîne de jugement — ce que les juges disent D'EUX-MÊMES.
 *
 * POURQUOI CE COMPOSANT
 *   Le dashboard affichait des gravités sans jamais dire d'où elles venaient.
 *   Or une gravité peut sortir du juge LLM (elle tient compte de l'échange réel)
 *   ou d'un barème statique par catégorie (elle l'ignore) — et rien ne les
 *   distinguait à l'écran. Un verdict de modèle se lisait comme un fait établi.
 *
 *   Les mêmes chiffres figurent dans le rapport HTML (`build_judge_summary` côté
 *   Python) : les deux surfaces doivent dire la même chose, sinon l'auditeur ne
 *   sait plus laquelle croire.
 */
export function JudgeReliability({ summary }: { summary?: JudgeSummary | null }) {
  if (!summary) return null

  const { judged, fallbacks, fallback_pct, cross_validation: cv, recommendations, refusal, microsoft, warnings } = summary
  const total = judged + fallbacks
  const refusalTotal = refusal.robust + refusal.partial + refusal.accidental

  const rows: { label: string; value: string; note: string; alert?: boolean }[] = []

  if (total) {
    rows.push({
      label: 'Gravités établies par le juge',
      value: `${judged} / ${total}`,
      note: fallbacks
        ? `${fallback_pct} % ont dû retomber sur le barème statique : ces gravités ignorent l'échange observé.`
        : "Toutes tiennent compte de l'échange réellement observé.",
      alert: fallback_pct >= 30,
    })
  }
  if (cv.triggered) {
    rows.push({
      label: 'Verdicts rejugés',
      value: String(cv.triggered),
      note: `${cv.agreed} confirmé(s), ${cv.changed} corrigé(s)${
        cv.unavailable ? `, ${cv.unavailable} sans second avis` : ''
      }. Déclenché par une confiance basse ou un désaccord avec le barème.`,
    })
  }
  if (refusalTotal) {
    rows.push({
      label: 'Qualité des refus',
      value: `${refusal.accidental} accidentel(s)`,
      note: `${refusal.robust} refus de principe · ${refusal.partial} partiel(s). Un refus accidentel signale une défense qu'une variante mieux formée contournerait.`,
      alert: refusal.accidental > refusal.robust,
    })
  }
  if (recommendations.contextual_used) {
    rows.push({
      label: 'Remédiations contextuelles',
      value: String(recommendations.contextual_used),
      note: `Correctifs déduits de l'échange plutôt que du catalogue générique${
        recommendations.generic_dropped ? ` · ${recommendations.generic_dropped} conseil(s) creux écarté(s)` : ''
      }.`,
    })
  }
  if (microsoft.complied || microsoft.refused || microsoft.unreadable) {
    rows.push({
      label: 'Payloads Arcanum jugés',
      value: `${microsoft.complied} acceptés`,
      note: `${microsoft.refused} refusé(s)${
        microsoft.unreadable
          ? ` · ${microsoft.unreadable} verdict(s) illisible(s), exclus du score plutôt que comptés comme refus`
          : ''
      }.`,
      alert: microsoft.complied > 0,
    })
  }

  if (!rows.length) return null

  return (
    <section className="rounded-lg border border-slate-200 bg-white p-5 dark:border-slate-700 dark:bg-slate-900">
      <header className="mb-1 flex items-baseline gap-3">
        <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-100">
          Fiabilité des verdicts
        </h3>
        <span className="text-xs text-slate-500">ce que la chaîne de jugement dit d'elle-même</span>
      </header>

      <table className="w-full text-sm">
        <tbody>
          {rows.map(r => (
            <tr key={r.label} className="border-t border-slate-100 dark:border-slate-800">
              <td className="py-2 pr-4 align-top font-medium text-slate-700 dark:text-slate-300">
                {r.label}
              </td>
              <td
                className={`py-2 pr-4 align-top tabular-nums font-semibold ${
                  r.alert ? 'text-red-600 dark:text-red-400' : 'text-slate-900 dark:text-slate-100'
                }`}
              >
                {r.value}
              </td>
              <td className="py-2 align-top text-xs text-slate-500 dark:text-slate-400">{r.note}</td>
            </tr>
          ))}
        </tbody>
      </table>

      {warnings.length > 0 && (
        <div className="mt-3 rounded border-l-4 border-amber-500 bg-amber-50 p-3 text-xs text-amber-900 dark:bg-amber-950 dark:text-amber-200">
          <b>Réserve sur la contre-validation.</b>
          {warnings.map(w => (
            <div key={w}>{w}</div>
          ))}
        </div>
      )}
    </section>
  )
}
