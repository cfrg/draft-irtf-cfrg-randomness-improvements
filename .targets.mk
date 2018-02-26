TARGETS_DRAFTS := draft-cremers-cfrg-randomness-improvements
TARGETS_TAGS := draft-sullivan-randomness-improvements-00 draft-sullivan-tls-random-improvemnents-00 draft-sullivan-tls-randomness-improvements-00
draft-cremers-cfrg-randomness-improvements-00.txt: draft-cremers-cfrg-randomness-improvements.txt
	sed -e s/draft-cremers-cfrg-randomness-improvements-latest/draft-cremers-cfrg-randomness-improvements-00/g -e s/draft-cremers-cfrg-randomness-improvements-latest/draft-cremers-cfrg-randomness-improvements-00/g -e s/draft-cremers-cfrg-randomness-improvements-latest/draft-cremers-cfrg-randomness-improvements-00/g $< >$@
