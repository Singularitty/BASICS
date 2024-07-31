never { /*   []!((p_0 || p_1 || p_2) && !(<>(p_3)))" */
accept_init:
	if
	:: (!p_0 && !p_1 && !p_2) || (p_3) -> goto accept_init
	:: (1) -> goto T0_S2
	fi;
T0_S2:
	if
	:: (1) -> goto T0_S2
	:: (p_3) -> goto accept_init
	fi;
}
