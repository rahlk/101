all: eg1

define hi
  echo "\n### $@ ######################\n"
endef

some=cut -d, -f 4,5,8,9 | sort -t, -n -k 4  | sed 's/,/,	/g'

Auto=cat $(Test)/data/auto.csv
Auto10=cat $(Test)/data/auto10000.csv
Auto1M=cat $(Test)/data/auto1M.csv
Weather=cat $(Test)/data/auto.csv
DSL= dsl/monte_carlo | dsl/brooks2

ok:; @bash $(Etc)/lua2bin

eg0: ok; @$(hi); $(DSL) | dom | bestrest | super | rank
eg1: ok; @$(hi); cat $(Test)/data/weather.csv | dom
eg2: ok; @$(hi); $(Auto) | dom | $(some); $(Auto) | head -1 | $(some)
eg3: ok; @$(hi); $(Auto) | dom | bestrest
eg4: ok; @$(hi); $(Auto) | dom | bestrest | super
eg5: ok; @$(hi); $(Auto) | dom | bestrest | super | rank
eg6: ok; @$(hi); $(Auto10) | dom | bestrest | super | rank
eg7: ok; @$(hi); $(Auto1M) | dom | bestrest | super | rank

