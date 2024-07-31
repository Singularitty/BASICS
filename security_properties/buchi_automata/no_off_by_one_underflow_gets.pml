never { /*   []!(p_0 V (<>(p_1)))  */
T0_init:
	if
	:: (!p_1) -> goto accept_S2
	:: (!p_0) -> goto T0_init
	fi;
accept_S2:
	if
	:: (!p_1) -> goto accept_S2
	fi;
}
