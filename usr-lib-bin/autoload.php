<?php
foreach(glob('./bin/*.php') as $key => $val){
	require_once($val);
}
