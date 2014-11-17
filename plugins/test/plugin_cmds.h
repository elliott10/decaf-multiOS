{
	.name		= "start_test_case",
	.args_type	= "",
	//.mhandler.cmd	= do_callbacktests,
	.mhandler.cmd	= vmi_test_init,
	.params		= "",
	.help		= "Run the test case."
},
{
	.name = "disable_test_case",
	.args_type = "", 
	.mhandler.cmd = test_cleanup,
	.params = "no params",
	.help = "disable test case." 
},
