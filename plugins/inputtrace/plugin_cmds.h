
{
	.name		= "taint_sendkey",
	.args_type	= "",
	.mhandler.cmd	= do_taint_sendkey,
	.params		= "",
	.help		= "send a tainted key to the guest system"
},
{
		.name = "enable_inputtrace_check",
		.args_type = "tracefile:F",
		.mhandler.cmd = do_enable_inputtrace_check,
		.params = "trace_file name",
		.help = "check every tainted instruction to see what module it belongs to "
},
{
		.name = "disable_inputtrace_check",
		.args_type = "",
		.mhandler.cmd = do_disable_inputtrace_check,
		.params = "no params",
		.help = "disable function that check every tainted instruction to see what module it belongs to "
},
