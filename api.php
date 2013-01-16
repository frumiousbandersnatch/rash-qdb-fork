<?php

require_once('settings.php');
require_once('DB.php');

define('USER_SUPERUSER', 1);
define('USER_ADMIN', 2);
define('USER_MOD', 3);
define('USER_NORMAL', 4);

function emit($data)
{
    header('Content-Type: application/json');
    // fsck, this only works in PHP 5.3+
    //print json_encode($data, JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES);
    print json_encode($data);
}



function check_cmd_auth($params)
{
    /* API command auth requirements.  You must have equal or less than this auth level */
    $readauth = USER_NORMAL;
    $writeauth = USER_NORMAL;
    $seequeue = USER_MOD;

    if (isset($params['login_required']) && $params['login_required'] == 1) {
        $addauth = USER_MOD;
    }
    if (isset($params['public_queue']) && $params['public_queue'] == 1) {
        $seequeue = USER_NORMAL;
    }

    $api = array(
        'napproved' => array('auth'=>$readauth),
        'npending'  => array('auth'=>$readauth),
        'add'       => array('auth'=>$writeauth, 'args'=>array('quote')),
        'vote'      => array('auth'=>$writeauth, 'args'=>array('qid','vote')), /* vote is 'up' or 'down' */
        'flag'      => array('auth'=>$writeauth),
        'get'       => array('auth'=>$readauth, 'args'=>array('qid')),
        'last'      => array('auth'=>$readauth),
        'latest'    => array('auth'=>$readauth, 'args'=>array('since')), /* since is Unix epoch time */
        'random'    => array('auth'=>$readauth),
        'search'    => array('auth'=>$readauth, 'args'=>array('pattern')),
        'approve'   => array('auth'=>$writeauth, 'args'=>array('qid','verdict')), /* verdict is 'approve' or 'remove' */
        'queue'     => array('auth'=>$seequeue),
    );

    if (!isset($params['cmd'])) {
        die ('No command given.');
    }
    $cmd = $params['cmd'];

    if (!isset($api[$cmd])) {
        die ("Unknown command: $cmd.");
    }
    $cmdapi = $api[$cmd];

    $needlevel = $cmdapi['auth'];
    if (!isset($params['login_level'])) {
        die ("No authentication level."); /* internal logic error */
    }
    $havelevel = $params['login_level'];

    if ($havelevel > $needlevel) {
        die ("Insufficient authentication level for command \"$cmd\".  Have $havelevel, need $needlevel.");
    }

    if (isset($cmdapi['args'])) {
        $args = $cmdapi['args'];
        foreach($args as $arg) {
            if (!isset($params[$arg])) {
                die ("Command \"$cmd\" requires argument \"$arg\".");
            }
        }
    }

    return $cmd;
}


function get_db($params)
{
    $dsn = array(
	     'phptype'  => $params['phptype'],
	     'username' => $params['username'],
	     'password' => $params['password'],
	     'hostspec' => $params['hostspec'],
	     'port'     => $params['port'],
	     'socket'   => $params['socket'],
	     'database' => $params['database'],
	     );
    $db =& DB::connect($dsn);
    if (DB::isError($db)) {
        die($db->getMessage());
    }
    return $db;
}
function dbintify($db, $data, $def=0)
{
    return $db->quote((int)$data,$def);
}

function tablename($params, $name)
{
    return $params['db_table_prefix'].'_'.$name;
}

function login($db, $params)
{
    $ret = array('login_user' => null,
                 'login_level' => USER_NORMAL,
                 'login_userid' => -1,
                 'logged_in' => 0);
    if (! (isset($params['rash_username']) && isset($params['rash_password']))) {
        return $ret;
    }

    $username = $params['rash_username'];
    $password = $params['rash_password'];

    //$tablename = $params['db_table_prefix'].'_users';
    $tablename = tablename($params, 'users');

    $ret['login_user'] = $username;

    $q = "SELECT salt FROM ".$tablename." WHERE LOWER(user)=".$db->quote(strtolower($username));
	$res =& $db->query($q);
	$salt = $res->fetchRow(DB_FETCHMODE_ASSOC);

    $sel = "SELECT * FROM ".$tablename." WHERE LOWER(user)=".$db->quote(strtolower($username));
	// if there is no presence of a salt, it is probably md5 since old rash used plain md5
	if (!$salt['salt']) {
        $q = $sel." AND `password` ='".md5($password)."'";
	    $res =& $db->query($q);
	    $row = $res->fetchRow(DB_FETCHMODE_ASSOC);
	}
	// if there is presense of a salt, it is probably new rash passwords, so it is salted md5
	else {
        $q = $sel." AND `password` ='".crypt($password, $salt['salt'])."'";
	    $res =& $db->query($q);
	    $row = $res->fetchRow(DB_FETCHMODE_ASSOC);
	}

	// if there is no row returned for the user, the password is expected to be false because of the AND conditional in the query
	if ($row['user']) {
        $ret = array('login_user' => $row['user'],
                     'login_level' => $row['level'],
                     'login_userid' => $row['id'],
                     'logged_in' => 1);
    }

    return $ret;
}


function make_query($db, $sql)
{
    $res =& $db->query($sql);
    if (DB::isError($res)) {
        die($res->getMessage());
    }
    while ($res->fetchInto($row, DB_FETCHMODE_ASSOC)) {
        $ret[] = $row;
    }
    return $ret;
}
function make_query_one($db, $sql, $index = null)
{
    $res =& $db->query($sql);
    if (DB::isError($res)) {
        die($res->getMessage());
    }
    $res->fetchInto($row, DB_FETCHMODE_ASSOC, $index);
    return $row;
}

function do_napproved($db, $params)
{
    $qt = tablename($params, 'quotes');
    return array('napproved' => $db->getOne('SELECT COUNT(id) FROM '.$qt.' where queue=0'));
}
function do_npending($db, $params)
{
    $qt = tablename($params, 'quotes');
    return array('npending' => $db->getOne('SELECT COUNT(id) FROM '.$qt.' where queue=1'));
}
function do_add($db, $params)
{
    $qt = tablename($params, 'quotes');
    $quote = $db->quote(stripcslashes($params['quote']));

    $flag = (isset($params['auto_flagged_quotes']) && ($params['auto_flagged_quotes'] == 1)) ? 2 : 0;
    $premod = $params['moderated_quotes'];
    $t = mktime();
    $db->query("INSERT INTO $qt (quote, rating, flag, queue, date) VALUES($quote, 0, $flag, $premod, '$t')");
    return make_query_one($db, "SELECT id FROM $qt where quote=$quote and date=$t");
}
function do_vote($db, $params)
{
    return array('error'=>'unimplemented');
}
function do_flag($db, $params)
{
    return array('error'=>'unimplemented');
}
function do_get($db, $params)
{
    $qid = $params['qid'];
    $qt = tablename($params, 'quotes');
    return make_query_one($db, 'SELECT * FROM '.$qt.' where id='.$qid);
}
function do_latest($db, $params)
{
    $qt = tablename($params, 'quotes');
    $since = $params['since'];
    return make_query($db, "SELECT * from $qt where queue=0 and date>=$since");
}
function do_last($db, $params)
{
    $qt = tablename($params, 'quotes');
    return make_query_one($db, "SELECT * FROM ".$qt." WHERE queue=0 ORDER BY id DESC LIMIT 1");
}
function do_random($db, $params)
{
    $qt = tablename($params, 'quotes');
    $count = $db->getOne('SELECT COUNT(id) FROM '.$qt.' where queue=0');
    $index = rand(0,$count-1);
    return make_query_one($db, 'SELECT * FROM '.$qt.' where queue=0', $index);
}
function do_search($db, $params)
{
    $qt = tablename($params, 'quotes');
    $pattern = $params['pattern'];
    return make_query($db, "SELECT * FROM $qt where queue=0 and quote like \"%$pattern%\"");
}

function do_approve($db, $params)
{
    $qt = tablename($params, 'quotes');
    $qid = dbintify($db, $params['qid'], -1);
    if ($qid < 0) {
        die ('Illegal quote id: '.$params['qid']);
    }
    $verdict = $params['verdict'];

    switch ($verdict) {
    case 'approve':
        $db->query("UPDATE $qt SET queue=0 WHERE id=$qid");
        break;
    case 'remove':
        print $db->query("DELETE FROM $qt WHERE queue=1 and id=$qid");
        break;
    default:
        die("Unknown verdict: \"$verdict\"");
    }
    return array('qid'=>$qid, 'verdict'=>$verdict);
}
function do_queue($db, $params)
{
    $qt = tablename($params, 'quotes');
    return make_query($db, "SELECT * FROM $qt where queue=1");    
}

function main()
{
    session_start();
    global $CONFIG, $_REQUEST, $_SESSION, $authmask;
    $params = array_merge($CONFIG, $_REQUEST, $_SESSION);

    $db = get_db($params);
    $params = array_merge($params, login($db, $params));

    $cmd = check_cmd_auth($params);

    $meth = sprintf("do_%s", $cmd);
    $ret = $meth($db, $params);
    $db->disconnect();
    
    emit($ret);

}

main();
