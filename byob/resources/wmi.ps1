$filter = ([wmiclass]"\\\\.\\root\\subscription:__EventFilter").CreateInstance()
$filter.QueryLanguage = "WQL"
$filter.Query = "Select * from __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA [STARTUP]"
$filter.Name = "[NAME]"
$filter.EventNamespace = 'root\\cimv2'

$result = $filter.Put()
$filterPath = $result.Path

$consumer = ([wmiclass]"\\\\.\\root\\subscription:CommandLineEventConsumer").CreateInstance()
$consumer.Name = '[NAME]'
$consumer.CommandLineTemplate = '[COMMAND_LINE]'
$consumer.ExecutablePath = ""
$consumer.WorkingDirectory = "C:\\Windows\\System32"
$result = $consumer.Put()
$consumerPath = $result.Path

$bind = ([wmiclass]"\\\\.\\root\\subscription:__FilterToConsumerBinding").CreateInstance()

$bind.Filter = $filterPath
$bind.Consumer = $consumerPath
$result = $bind.Put()
$bindPath = $result.Path