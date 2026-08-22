import { useState, useMemo } from 'react'
import { motion } from 'framer-motion'
import {
  ArrowRight, TrendingDown, TrendingUp, Minus, TriangleAlert as AlertTriangle,
  Info, Repeat,
} from 'lucide-react'
import { useApp } from '@/App'
import { getAudits , useAudits} from '@/data/repository'
import { signature, inferMode, targetOf, MODE_LABEL, axisScores, AXES } from '@/data/insights'
import { ASI_CATEGORIES } from '@/types'
import type { AttackVerdict, Audit } from '@/types'

type Tab = 'category' | 'attack'

/**
 * Sélection par défaut : la paire la plus RÉCENTE qui soit réellement comparable
 * (même cible, même mode, mêmes axes). Sans ça, le défaut tombait sur deux
 * catégories différentes — toutes les lignes vides et un écart de score
 * dépourvu de sens.
 */
function defaultPair(audits: Audit[]): [string, string] {
  for (let i = 0; i < audits.length; i++) {
    const sig = signature(audits[i])
    for (let j = i + 1; j < audits.length; j++) {
      if (signature(audits[j]) === sig) return [audits[j].id, audits[i].id]  // ancien → récent
    }
  }
  return [audits[Math.min(1, audits.length - 1)].id, audits[0].id]
}

export function ComparisonPage() {
  const { setCurrentPage } = useApp()
  useAudits()   // abonnement : rafraîchit après un audit
  const [defA, defB] = useMemo(() => defaultPair(getAudits()), [])
  const [auditAId, setAuditAId] = useState(defA)
  const [auditBId, setAuditBId] = useState(defB)
  const [tab, setTab] = useState<Tab>('category')

  const auditA = getAudits().find(a => a.id === auditAId)!
  const auditB = getAudits().find(a => a.id === auditBId)!

  const delta = auditB.global_score - auditA.global_score
  const comparable = signature(auditA) === signature(auditB)

  const categoryDeltas = useMemo(() => {
    return ASI_CATEGORIES.map(cat => {
      const agentA = auditA.agents.find(a => a.asi_category === cat.id)
      const agentB = auditB.agents.find(a => a.asi_category === cat.id)
      const scoreA = agentA?.status === 'completed' ? agentA.score : null
      const scoreB = agentB?.status === 'completed' ? agentB.score : null
      const d = (scoreA !== null && scoreB !== null) ? scoreB - scoreA : null
      return { category: cat, scoreA, scoreB, delta: d }
    })
  }, [auditA, auditB])

  /**
   * Écart PAR AXE, pour chaque catégorie présente dans les DEUX audits.
   *
   * POURQUOI CETTE VUE
   *     La table par catégorie ne montre que le score consolidé de l'agent. Or
   *     l'information utile est ailleurs : deux audits peuvent différer de 20
   *     points alors qu'un SEUL axe a bougé. Sans ce détail, on ne sait pas si
   *     l'écart vient de DeepTeam, de PyRIT ou de Garak — donc on ne sait pas
   *     ce qu'il faut en conclure.
   *
   *     Cas typique : Garak ne dépend d'aucun LLM (ses probes SONT les attaques).
   *     S'il est identique des deux côtés, la cible n'a pas changé et tout l'écart
   *     est imputable aux axes pilotés par un modèle.
   */
  const axisDeltas = useMemo(() => {
    const out: { category: string; rows: { axis: string; a: number | null; b: number | null; delta: number | null }[] }[] = []
    auditA.agents.forEach(agA => {
      const agB = auditB.agents.find(x => x.asi_category === agA.asi_category)
      if (!agB) return
      const cA = axisScores(agA)
      const cB = axisScores(agB)
      const rows = AXES
        .filter(k => cA[k] != null || cB[k] != null)
        .map(k => {
          const a = cA[k] ?? null
          const b = cB[k] ?? null
          return { axis: k, a, b, delta: a !== null && b !== null ? b - a : null }
        })
      if (rows.length) out.push({ category: agA.asi_category, rows })
    })
    return out
  }, [auditA, auditB])

  /**
   * Comparaison attaque par attaque.
   *
   * APPARIEMENT PAR PROMPT, pas par nom de technique.
   *     Un audit contient 9 attaques nommées « Base64 » : apparier par technique
   *     associerait la première de A à la première de B — deux prompts sans
   *     rapport. Les régressions rapportées seraient alors inventées.
   *     Deux attaques ne sont identiques que si leur PROMPT l'est.
   *
   * CONSÉQUENCE ASSUMÉE
   *     Le simulateur génère de nouvelles attaques à chaque exécution : deux
   *     audits indépendants n'ont donc presque aucun prompt en commun, et la
   *     vue reste vide. Ce n'est pas un défaut, c'est le constat honnête —
   *     seul un REJEU renvoie les mêmes prompts et rend la comparaison possible.
   */
  const attackDiff = useMemo(() => {
    const norm = (s: string) => s.trim().replace(/\s+/g, ' ').slice(0, 400)

    /**
     * Identité d'une attaque.
     *
     * Le PROMPT est la clé de référence : c'est ce qui définit « la même attaque ».
     * Mais les axes déterministes — Garak, PyRIT, Semgrep, sandbox — n'exposaient
     * pas de prompt dans les audits antérieurs au journal unifié, et leur identité
     * ne dépend de toute façon pas d'un prompt généré : une sonde Garak porte
     * toujours le même nom. On retombe donc sur `axe + technique` pour eux.
     */
    const keyOf = (a: { category: string; prompt: string; axis: string; technique: string }) =>
      a.prompt.trim()
        ? `${a.category}::p::${norm(a.prompt)}`
        : `${a.category}::t::${a.axis}::${a.technique}`

    const changes: {
      technique: string; category: string; prompt: string
      verdictA: AttackVerdict; verdictB: AttackVerdict
      change_type: 'regression' | 'correction' | 'new_flaw'
    }[] = []

    const flat = (a: typeof auditA) =>
      a.agents.flatMap(ag => ag.attacks.map(atk => ({ ...atk, category: ag.asi_category })))
    const attacksA = flat(auditA)
    const attacksB = flat(auditB)

    // Même audit des deux côtés : tout est commun par construction.
    if (auditA.id === auditB.id) {
      return { changes: [], matched: attacksA.length, identical: true,
               totalA: attacksA.length, totalB: attacksB.length }
    }

    const indexA = new Map(attacksA.map(a => [keyOf(a), a]))
    let matched = 0

    attacksB.forEach(atkB => {
      const atkA = indexA.get(keyOf(atkB))
      if (!atkA) {
        // Attaque inédite : seule une percée mérite d'être signalée.
        if (atkB.verdict === 'compromised') {
          changes.push({
            technique: atkB.technique, category: atkB.category, prompt: atkB.prompt,
            verdictA: 'excluded', verdictB: atkB.verdict, change_type: 'new_flaw',
          })
        }
        return
      }
      matched += 1
      if (atkA.verdict === 'resisted' && atkB.verdict === 'compromised') {
        changes.push({ technique: atkB.technique, category: atkB.category, prompt: atkB.prompt,
                       verdictA: atkA.verdict, verdictB: atkB.verdict, change_type: 'regression' })
      } else if (atkA.verdict === 'compromised' && atkB.verdict === 'resisted') {
        changes.push({ technique: atkB.technique, category: atkB.category, prompt: atkB.prompt,
                       verdictA: atkA.verdict, verdictB: atkB.verdict, change_type: 'correction' })
      }
    })

    return { changes, matched, identical: false,
             totalA: attacksA.length, totalB: attacksB.length }
  }, [auditA, auditB])

  const attackChanges = attackDiff.changes

  return (
    <div className="p-6 space-y-4">
      <div className="flex items-center gap-3 flex-wrap">
        <AuditSelector value={auditAId} onChange={setAuditAId} label="Audit A" />
        <ArrowRight size={20} className="text-text-muted" />
        <AuditSelector value={auditBId} onChange={setAuditBId} label="Audit B" />
      </div>
      {!comparable && (
        <div className="card p-4 border-l-4 flex items-start gap-3"
             style={{ borderLeftColor: 'var(--sev-high)' }}>
          <AlertTriangle size={16} className="text-severity-high mt-0.5 shrink-0" />
          <p className="text-sm text-text-secondary">
            <b className="text-severity-high">Audits non comparables.</b>{' '}
            {targetOf(auditA)} en mode {MODE_LABEL[inferMode(auditA)].toLowerCase()} contre{' '}
            {targetOf(auditB)} en mode {MODE_LABEL[inferMode(auditB)].toLowerCase()} — ils
            n'ont pas exécuté les mêmes axes sur le même périmètre. L'écart de score
            ne mesure pas une évolution de sécurité.
          </p>
        </div>
      )}

      {/* Même cible, même périmètre, mais profils LLM différents : c'est une
          EXPÉRIENCE À VARIABLE UNIQUE, pas une évolution dans le temps. Le dire
          explicitement évite de lire l'écart comme « la sécurité s'est dégradée »
          alors qu'on mesure la force de l'attaquant. */}
      {comparable && auditA.profile !== auditB.profile
        && targetOf(auditA) === targetOf(auditB) && (
        <div className="card p-4 border-l-4 flex items-start gap-3"
             style={{ borderLeftColor: 'var(--sev-info)' }}>
          <Info size={16} className="text-severity-info mt-0.5 shrink-0" />
          <p className="text-sm text-text-secondary">
            <b className="text-text-primary">Comparaison à variable unique.</b>{' '}
            Même cible et mêmes axes ; seul le <b>profil LLM</b> change —{' '}
            <b className="text-text-primary">{auditA.profile}</b> contre{' '}
            <b className="text-text-primary">{auditB.profile}</b>. L'écart mesure donc
            la <b>force de l'attaquant</b>, pas une évolution de la sécurité de la cible.
            L'axe Garak, indépendant de tout LLM, sert de témoin : s'il est identique
            des deux côtés, la cible n'a pas changé.
          </p>
        </div>
      )}

      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        className="card p-6"
      >
        <div className="text-xs font-semibold uppercase tracking-wider text-text-secondary mb-3">
          Écart du score global
        </div>
        <div className="flex items-center gap-6">
          <div>
            <div className="text-xs text-text-muted">Audit A</div>
            <div className="text-2xl font-bold font-mono text-text-primary">{auditA.global_score}</div>
          </div>
          <div className="flex flex-col items-center">
            <DeltaIcon delta={delta} />
            <div className="text-3xl font-bold font-mono" style={{
              color: delta > 0 ? '#00D68F' : delta < 0 ? '#FF3B5C' : '#8B96AE'
            }}>
              {delta > 0 ? '+' : ''}{delta.toFixed(1)}
            </div>
          </div>
          <div>
            <div className="text-xs text-text-muted">Audit B</div>
            <div className="text-2xl font-bold font-mono text-text-primary">{auditB.global_score}</div>
          </div>
        </div>
      </motion.div>

      <div className="flex gap-2">
        <button
          onClick={() => setTab('category')}
          className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors
            ${tab === 'category' ? 'bg-brand/10 text-brand border border-brand/30' : 'bg-bg-surface text-text-secondary border border-border'}`}
        >
          Par catégorie
        </button>
        <button
          onClick={() => setTab('attack')}
          className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors
            ${tab === 'attack' ? 'bg-brand/10 text-brand border border-brand/30' : 'bg-bg-surface text-text-secondary border border-border'}`}
        >
          Par attaque {attackChanges.length > 0 && (
            <span className="ml-1 px-1.5 py-0.5 rounded-md bg-severity-high/20 text-severity-high text-[10px] font-bold">
              {attackChanges.length}
            </span>
          )}
        </button>
      </div>

      {tab === 'category' && (
        <div className="card overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left px-4 py-3 text-xs font-semibold uppercase tracking-wider text-text-secondary">Catégorie</th>
                <th className="text-right px-4 py-3 text-xs font-semibold uppercase tracking-wider text-text-secondary">Audit A</th>
                <th className="text-right px-4 py-3 text-xs font-semibold uppercase tracking-wider text-text-secondary">Audit B</th>
                <th className="text-right px-4 py-3 text-xs font-semibold uppercase tracking-wider text-text-secondary">Delta</th>
              </tr>
            </thead>
            <tbody>
              {categoryDeltas.map(d => (
                <tr key={d.category.id} className="border-b border-border-subtle">
                  <td className="px-4 py-3">
                    <span className="font-mono text-xs text-text-muted">{d.category.short}</span>
                    <span className="text-text-secondary ml-2">{d.category.name}</span>
                  </td>
                  <td className="px-4 py-3 text-right font-mono text-text-secondary">
                    {d.scoreA !== null ? d.scoreA.toFixed(1) : '—'}
                  </td>
                  <td className="px-4 py-3 text-right font-mono text-text-secondary">
                    {d.scoreB !== null ? d.scoreB.toFixed(1) : '—'}
                  </td>
                  <td className="px-4 py-3 text-right font-mono font-bold">
                    {d.delta === null ? (
                      <span className="text-text-muted">—</span>
                    ) : (
                      <span style={{
                        color: d.delta > 0 ? '#00D68F' : d.delta < 0 ? '#FF3B5C' : '#8B96AE'
                      }}>
                        {d.delta > 0 ? '+' : ''}{d.delta.toFixed(1)}
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {tab === 'category' && axisDeltas.map(({ category, rows }) => (
        <div key={category} className="card overflow-hidden">
          <div className="px-4 py-3 border-b border-border flex items-baseline gap-2">
            <span className="text-xs font-semibold uppercase tracking-wider text-text-secondary">
              Détail par axe
            </span>
            <span className="font-mono text-xs text-text-muted">{category}</span>
          </div>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left px-4 py-2.5 text-xs font-semibold uppercase tracking-wider text-text-secondary">Axe</th>
                <th className="text-right px-4 py-2.5 text-xs font-semibold uppercase tracking-wider text-text-secondary">Audit A</th>
                <th className="text-right px-4 py-2.5 text-xs font-semibold uppercase tracking-wider text-text-secondary">Audit B</th>
                <th className="text-right px-4 py-2.5 text-xs font-semibold uppercase tracking-wider text-text-secondary">Delta</th>
              </tr>
            </thead>
            <tbody>
              {rows.map(r => (
                <tr key={r.axis} className="border-b border-border-subtle">
                  <td className="px-4 py-2.5">
                    <span className="text-text-secondary capitalize">{r.axis}</span>
                    {r.axis === 'garak' && (
                      <span className="ml-2 text-[10px] text-text-muted">
                        témoin — indépendant du LLM
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-2.5 text-right font-mono text-text-secondary">
                    {r.a !== null ? r.a.toFixed(2) : 'exclu'}
                  </td>
                  <td className="px-4 py-2.5 text-right font-mono text-text-secondary">
                    {r.b !== null ? r.b.toFixed(2) : 'exclu'}
                  </td>
                  <td className="px-4 py-2.5 text-right font-mono font-bold">
                    {r.delta === null ? (
                      <span className="text-text-muted">—</span>
                    ) : (
                      <span style={{
                        color: r.delta > 0 ? '#00D68F' : r.delta < 0 ? '#FF3B5C' : '#8B96AE',
                      }}>
                        {r.delta > 0 ? '+' : ''}{r.delta.toFixed(2)}
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ))}

      {tab === 'attack' && (
        <div className="space-y-2">
          {/* Bilan d'appariement — l'information la plus importante de cette vue. */}
          <div className="card p-4 flex items-center gap-5 flex-wrap">
            <Tally label="Attaques communes" value={attackDiff.matched}
                   color={attackDiff.matched ? 'var(--sev-info)' : 'var(--sev-high)'} />
            <Tally label="Régressions"
                   value={attackChanges.filter(c => c.change_type === 'regression').length}
                   color="var(--sev-critical)" />
            <Tally label="Corrections"
                   value={attackChanges.filter(c => c.change_type === 'correction').length}
                   color="var(--sev-low)" />
            <Tally label="Nouvelles failles"
                   value={attackChanges.filter(c => c.change_type === 'new_flaw').length}
                   color="var(--sev-high)" />
            <span className="ml-auto text-[11px] text-text-muted">
              {attackDiff.totalA} attaques dans A · {attackDiff.totalB} dans B
            </span>
          </div>

          {attackDiff.identical && (
            <div className="card p-5 border-l-4 flex items-start gap-3"
                 style={{ borderLeftColor: 'var(--sev-info)' }}>
              <Info size={17} className="text-severity-info mt-0.5 shrink-0" />
              <p className="text-sm text-text-secondary">
                Vous comparez un audit <b>avec lui-même</b> : les {attackDiff.totalA} attaques
                sont identiques et aucun écart n'est possible. Choisissez deux audits distincts.
              </p>
            </div>
          )}

          {!attackDiff.identical && attackDiff.matched === 0 && (
            <div className="card p-5 border-l-4 flex items-start gap-3"
                 style={{ borderLeftColor: 'var(--sev-info)' }}>
              <Info size={17} className="text-severity-info mt-0.5 shrink-0" />
              <div>
                <p className="text-sm text-text-primary font-medium">
                  Aucune attaque commune — c'est le comportement attendu.
                </p>
                <p className="text-sm text-text-secondary mt-1.5 max-w-3xl">
                  Le simulateur génère de nouvelles attaques à chaque exécution. Deux
                  audits indépendants n'envoient donc jamais les mêmes prompts, et
                  comparer leurs verdicts reviendrait à comparer des choses différentes.
                  Pour vérifier si une faille est corrigée, il faut{' '}
                  <b>renvoyer exactement les mêmes attaques</b>.
                </p>
                <button
                  onClick={() => setCurrentPage('attacks')}
                  className="mt-3 px-3.5 py-2 rounded-xl bg-brand text-white text-xs font-semibold
                             flex items-center gap-2 hover:bg-brand-dark transition-colors"
                >
                  <Repeat size={13} /> Lancer un rejeu depuis la page Attaques
                </button>
              </div>
            </div>
          )}

          {!attackDiff.identical && attackDiff.matched > 0 && attackChanges.length === 0 && (
            <div className="card p-8 text-center text-text-muted">
              {attackDiff.matched} attaque(s) commune(s), aucun changement de verdict.
            </div>
          )}
          {attackChanges.map((c, i) => {
            const cat = ASI_CATEGORIES.find(x => x.id === c.category)
            const config = {
              regression: { color: '#FF3B5C', bg: 'bg-severity-critical/5', border: 'border-severity-critical/30', label: 'RÉGRESSION', icon: TrendingDown },
              correction: { color: '#00D68F', bg: 'bg-severity-low/5', border: 'border-severity-low/30', label: 'CORRECTION', icon: TrendingUp },
              new_flaw: { color: '#FF8C00', bg: 'bg-severity-high/5', border: 'border-severity-high/30', label: 'NOUVELLE FAILLE', icon: AlertTriangle },
              unchanged: { color: '#8B96AE', bg: '', border: 'border-border', label: 'Inchangé', icon: Minus },
            }[c.change_type]
            const Icon = config.icon
            return (
              <motion.div
                key={i}
                initial={{ opacity: 0, x: -10 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: i * 0.05 }}
                className={`rounded-lg border ${config.border} ${config.bg} p-3 flex items-center gap-3`}
              >
                <Icon size={18} style={{ color: config.color }} />
                <span className={`px-2 py-0.5 rounded-md text-[10px] font-bold`} style={{
                  backgroundColor: `${config.color}15`, color: config.color
                }}>
                  {config.label}
                </span>
                <span className="font-mono text-xs text-text-muted">{cat?.short}</span>
                <span className="text-sm text-text-primary flex-1">{c.technique}</span>
                <span className="text-xs text-text-secondary">
                  {c.verdictA === 'excluded' ? '—' : c.verdictA} → {c.verdictB}
                </span>
              </motion.div>
            )
          })}
        </div>
      )}
    </div>
  )
}

function AuditSelector({ value, onChange, label }: {
  value: string; onChange: (v: string) => void; label: string
}) {
  return (
    <div>
      <label className="text-xs font-semibold uppercase tracking-wider text-text-secondary mb-1.5 block">{label}</label>
      <select
        value={value}
        onChange={e => onChange(e.target.value)}
        className="px-3 py-2 rounded-lg bg-bg-surface border border-border text-sm text-text-primary outline-none min-w-[240px]"
      >
        {getAudits().map(a => (
          <option key={a.id} value={a.id}>
            {a.target_name} — {a.profile} — {a.global_score}/100 ({a.started_at.slice(0, 10)})
          </option>
        ))}
      </select>
    </div>
  )
}

function DeltaIcon({ delta }: { delta: number }) {
  if (delta > 0) return <TrendingUp size={24} className="text-severity-low mb-1" />
  if (delta < 0) return <TrendingDown size={24} className="text-severity-critical mb-1" />
  return <Minus size={24} className="text-text-muted mb-1" />
}

function Tally({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div>
      <div className="text-[10px] font-semibold uppercase tracking-wider text-text-muted">
        {label}
      </div>
      <div className="font-mono text-xl font-bold tabular leading-none mt-1" style={{ color }}>
        {value}
      </div>
    </div>
  )
}
