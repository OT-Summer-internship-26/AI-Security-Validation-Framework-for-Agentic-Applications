@echo off
REM ============================================================================
REM  Sauvegarde PLANIFIEE du volume de donnees.
REM
REM  POURQUOI CE FICHIER EXISTE
REM      `scripts/backup_volume.py` existait, etait teste et documente — mais
REM      n'etait PLANIFIE nulle part. Il reposait donc entierement sur la memoire
REM      de l'operateur, pour un volume qui porte la base d'etat, la file, les
REM      CLES D'API (dont seules les empreintes sont stockees : une cle perdue ne
REM      se retrouve pas) et des heures de calcul deja payees.
REM      Verifie le jour ou ce script a ete ecrit : AUCUNE sauvegarde n'existait.
REM
REM  A ENREGISTRER UNE FOIS (invite de commandes en administrateur) :
REM
REM      schtasks /Create /TN "AI Security - sauvegarde" ^
REM               /TR "\"%~f0\"" /SC DAILY /ST 02:00
REM
REM  Verifier ensuite :   schtasks /Query /TN "AI Security - sauvegarde"
REM  Supprimer :          schtasks /Delete /TN "AI Security - sauvegarde" /F
REM
REM  SOUS LINUX, l'equivalent en cron :
REM      0 2 * * * cd /chemin/du/depot && python scripts/backup_volume.py --sauvegarder >> sauvegardes/journal.txt 2>&1
REM
REM  CE QUE CE SCRIPT NE FAIT PAS : verifier que la planification tourne encore.
REM  C'est le role de `--verifier`, a brancher sur la supervision :
REM      python scripts/backup_volume.py --verifier
REM  Code de sortie non nul si la derniere sauvegarde a plus de 26 h.
REM ============================================================================
cd /d "%~dp0"

if not exist "sauvegardes" mkdir "sauvegardes"

echo. >> "sauvegardes\journal.txt"
echo ===== %DATE% %TIME% ===== >> "sauvegardes\journal.txt"

REM La sortie va DANS le journal : une tache planifiee n'a pas de console, et un
REM echec sans trace est un echec qu'on decouvre a la restauration.
python scripts\backup_volume.py --sauvegarder >> "sauvegardes\journal.txt" 2>&1
set CODE=%ERRORLEVEL%

if %CODE% NEQ 0 (
    echo ECHEC de la sauvegarde ^(code %CODE%^) >> "sauvegardes\journal.txt"
) else (
    echo Sauvegarde OK >> "sauvegardes\journal.txt"
)

REM Le code de sortie est PROPAGE : c'est lui que le Planificateur de taches
REM affiche en « Dernier resultat de l'execution ». Le perdre ferait passer un
REM echec pour un succes dans la seule interface que l'operateur regarde.
exit /b %CODE%
