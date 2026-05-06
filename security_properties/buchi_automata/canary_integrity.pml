never { /* G(!p_0 | p_1) */
accept_init:
  if
  :: ((!(p_0)) || (p_1)) -> goto accept_init
  fi;
}
