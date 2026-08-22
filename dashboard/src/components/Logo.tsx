// Logo Ooredoo officiel — fichier d'origine servi depuis dashboard/public/.
// Source 708x282 : affiché à 40px de haut, soit ~5x la densité nécessaire,
// donc net sur écran HiDPI et vidéoprojecteur.
const logoUrl = '/ooredoo-logo.jpg'

/**
 * L'image d'origine est sur fond blanc. En thème clair on la pose directement
 * (le fond de la sidebar est déjà clair) ; en thème sombre on la garde sur une
 * pastille blanche plutôt que de la détourer, pour ne pas altérer la marque.
 */
export function Logo({ collapsed = false }: { collapsed?: boolean }) {
  if (collapsed) {
    return (
      <div
        className="w-11 h-11 rounded-2xl bg-white overflow-hidden flex items-center
                   justify-center shadow-card ring-1 ring-black/5"
        title="Ooredoo — Security Audit Console"
      >
        <img
          src={logoUrl}
          alt="Ooredoo"
          className="w-[190%] max-w-none object-cover object-left"
          draggable={false}
        />
      </div>
    )
  }

  return (
    <div className="rounded-xl bg-white px-3 py-2 shadow-card ring-1 ring-black/5">
      <img
        src={logoUrl}
        alt="Ooredoo"
        className="h-10 w-auto block"
        draggable={false}
      />
    </div>
  )
}
