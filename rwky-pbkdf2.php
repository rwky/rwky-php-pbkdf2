<?php
namespace RWKY;
/**
 *Provides PBKDF2 functionality as specified in RFC 2989 http://www.ietf.org/rfc/rfc2898.txt
 *@copyright Rowan Wookey 2011 admin@rwky.net Released under the simplified BSD license see LICENSE file or http://www.opensource.org/licenses/BSD-2-Clause
 **/
class PBKDF2
{
  /**
   *The version of this class
   */
  const VERSION=2011102200;
  /**
   *The salt for the password, a minimum of 64 bit is recommended
   */
  private $_salt;
  /**
   *The password to be hashed
   */
  private $_password;
  /**
   *how many iterations to perform, 10000 minimum recomended if you have a system with a fast cpu then the higher the better, note that the number of iterations is multiplied by the block count which is calculated by the $dkLen divided by the length of the hash (sha 512 is 128)
   */
  private $_iterations;
  /**
   *the hash algorithm to use, any from hash_algos() maybe used see http://uk3.php.net/manual/en/function.hash-algos.php
   */
  private $_hashAlgorithm;
  /**
   *The derived key
   */
  private $_key='';
  /**
   *The block number we're working on
   */
  private $_blockNumber=0;
  /**
   *the desired length of the key
   */
  private $_dkLen;
  /**
   *the length of the hash
   */
  private $_hLen;
  /**
   *the number of blocks to generate
   */
  private $_blockCount;
  
  /**
   *Construct a new PBKDF2 object and prepare it for generation
   *@param string $password the password to hash
   *@param string|null $salt the salt to use, a minimum 64 bit hash which is unique to each password is recommended, if null is provided a 128 bit salt will be generated, if on windows generate your own salt and pass it since windows doesn't have /dev/urandom which generates the salt
   *@param int $iterations the number of iterations
   *@param int|null $dkLen the length of the desired key, defaults to the hash length
   *@param string $hashAlgorithm the hash algoritm to use, see hash_algos() http://uk3.php.net/manual/en/function.hash-algos.php
  */
  public function __construct($password,$salt=null,$iterations=10000,$dkLen=null,$hashAlgorithm="sha512") {
   
    $this->_password=$password;
    if(strlen($this->_password)<1) throw new \Exception("Password must not be empty");
    
    $this->_salt=!is_null($salt) ? $salt : $this->generateSalt(128);
    $this->_iterations=$iterations;
    $this->_hashAlgorithm=$hashAlgorithm;
    
    if(!in_array($this->_hashAlgorithm,hash_algos())) throw new \Exception("Unknown hash algorithm: ".$this->_hashAlgorithm);
    
    $this->_hLen=strlen($this->_prf(0));
    $this->_dkLen=!is_null($dkLen) ? $dkLen : $this->_hLen;
    $this->_blockCount=ceil($this->_dkLen/$this->_hLen);
    if($this->_dkLen < 1 or $this->_dkLen > 4294967295 * $this->_hLen) throw new \Exception("Derived key wrong length, min:1 max: ".(4294967295 * $this->_hLen));
    
  }
  
  /**
   *Generates a salt using /dev/urandom this will not work on windows
   *@param int $bits the number of bits to generate
   *@return returns a salt $bits bits long
   */
  
  public function generateSalt($bits)
  {
    $f=fopen('/dev/urandom','rb');
    $data=fread($f,$bits/8);
    fclose($f);
    return $data;
  }
  
  /**
   *Returns the length of the hash
   *@return int the length of the hash
   */
  public function getHlen()
  {
    return $this->_hLen;
  }
  
  /**
   *Returns the salt, you need to store this along with the password to perform comparisons
   */
  public function getSalt()
  {
    return $this->_salt;
  }
  
  /**
   *Returns the number of iterations
   */
  public function getIterations()
  {
    return $this->_iterations;
  }
  
  /**
   *returns the hash algorithm used
   */
  public function getHashAlogorithm()
  {
    return $this->_hashAlgorithm;
  }
  
  /**
   *returns the derived key length
   */
  public function getDkLen()
  {
    return $this->_dkLen;
  }
  
   /**
    *returns the derived key
    */
   public function getKey()
   {
      return $this->_key;
   }
  
  /**
   *Generate the key
   *@return the derived key which is $this->_dkLen octets long
   */
  public function generate()
  {
    while($this->_blockNumber < $this->_blockCount)
    {
      ++$this->_blockNumber;
      $this->_key.=$this->_block($this->_blockNumber);
    }
    $this->_key=substr($this->_key,0,$this->_dkLen);
    return $this->_key;
  }
  
  /**
   *Compares a plain text password with a stored key
   *@param string $key the key to compare with
   *@return bool true if the stored key and generated key are the same
   */
  public function compare($key)
  {
    if($this->_key=='') $this->generate();
    return $this->_key==$key;
  }
  
  /**
   *@param string $data the data to hash
   *@return string the hashed data in binary form
   */
  private function _prf($data)
  {
    $hash=hash_hmac($this->_hashAlgorithm,$data,$this->_password,true);
    if($hash===false) throw new \Exception("Unable to hash block");
    return $hash;
  }
  
  /**
   *Generate the hash for the block this is the function F specified in the RFC
   *@param int $i the block number to work on
   *@return the hash for the block
   */
  private function _block($i)
  {
    if($i < 1 or $i > 4294967296) throw new Exception('$i must be an unsigned int, passed '.$i);
    $U = $this->_prf($this->_salt.pack('N',$i));
    
    $result = $U;
    for($j=2;$j<=$this->_iterations;++$j)
    {
      $U = $this->_prf($U);
      $result ^= $U;
    }
    return $result;
  }
  
}


