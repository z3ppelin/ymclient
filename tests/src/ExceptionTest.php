<?php
/**
 * Unit test for \bogcon\ymclient\Exception class.
 * 
 * @author      Bogdan Constantinescu <bog_con@yahoo.com>
 * @link        GitHub  https://github.com/z3ppelin/ymclient.git
 * @licence     The BSD License (http://opensource.org/licenses/BSD-3-Clause); see LICENSE.txt
 */
namespace bogcon\ymclient\tests;

/**
 * @covers \bogcon\ymclient\Exception
 */
class ExceptionTest extends \PHPUnit_Framework_TestCase
{
    /**
     * Test custom exception extends standard exception.
     * @coversNothing
     */
    public function testIsAnException()
    {
        $objEx = new \bogcon\ymclient\Exception('Exception message');
        $this->assertTrue($objEx instanceof \Exception);
    }
}
