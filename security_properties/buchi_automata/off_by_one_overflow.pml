never { /*   []((p_0) -> !(<>(p_1)))  */
accept_init:
	if
	:: (!p_0) -> goto accept_S1
	:: (!p_1) -> goto accept_S2
	fi;
accept_S1:
	if
	:: (!p_0) -> goto accept_S1
	:: (!p_1) -> goto accept_S2
	fi;
accept_S2:
	if
	:: (!p_0 && !p_1) || (!p_1) -> goto accept_S2
	fi;
}
