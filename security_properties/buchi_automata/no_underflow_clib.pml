never { /* !p_0 U G!p_1 */
T0_init:
  if
  :: (!(p_0)) -> goto T0_init
  :: (!(p_1)) -> goto accept_S1
  fi;
accept_S1:
  if
  :: (!(p_1)) -> goto accept_S1
  fi;
}
