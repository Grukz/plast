rule Hello
{
	strings:
		$ascii_string = "hello"

	condition:
		$ascii_string
}
