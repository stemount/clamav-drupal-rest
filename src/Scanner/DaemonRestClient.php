<?php

namespace Drupal\clamav\Scanner;

use Drupal\file\FileInterface;
use Drupal\clamav\ScannerInterface;
use Drupal\clamav\Scanner;
use Drupal\clamav\Config;

class DaemonRestClient implements ScannerInterface {
  protected $_file;
  protected $_endpoint;
  protected $_port;
  protected $_virus_name = '';

  /**
   * {@inheritdoc}
   */
  public function __construct(Config $config) {
    $this->_endpoint = $config->get('mode_daemon_rest_client.endpoint');
  }

  /**
   * {@inheritdoc}
   */
  public function scan(FileInterface $file) {

    $ch = curl_init();
    $filePath = $file->getFileUri();
    $file_name = basename($filePath);

    $post_fields = [
      'name' => $file_name,
      'file' => new \CurlFile($filePath, mime_content_type($filePath), $file_name)
    ];

    curl_setopt($ch, CURLOPT_URL, $this->_endpoint);
    curl_setopt($ch, CURLOPT_POST, TRUE);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $post_fields);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);

    $response = trim(curl_exec($ch));

    curl_close($ch);

    // Process the output from the service.
    if (preg_match('/^Everything ok : true$/', $response)) {
      $result = Scanner::FILE_IS_CLEAN;
    }
    elseif (preg_match('/^Everything ok : false$/', $response, $matches)) {
      $this->_virus_name = 'unknown';
      $result = Scanner::FILE_IS_INFECTED;
    }
    else {
      preg_match('/^Internal Server Error$/', $response, $matches);
      $result = Scanner::FILE_IS_UNCHECKED;
    }

    return $result;

  }

  /**
   * {@inheritdoc}
   */
  public function virus_name() {
    return $this->_virus_name;
  }

  /**
   * {@inheritdoc}
   */
  public function version() {
    return 'rest client';
  }
}
