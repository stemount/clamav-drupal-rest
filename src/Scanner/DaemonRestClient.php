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
  protected $_httpclient;

  /**
   * {@inheritdoc}
   */
  public function __construct(Config $config) {
    $this->_endpoint = $config->get('mode_daemon_rest_client.endpoint');

    $this->_httpclient = \Drupal::httpClient();
  }

  /**
   * {@inheritdoc}
   */
  public function scan(FileInterface $file) {

    $result = Scanner::FILE_IS_UNCHECKED;

    try {
      $file_post = $this->_httpclient->post($this->_endpoint, [
        'multipart' => [
          [
            'name' => 'file',
            'contents' => fopen($file->getFileUri(), 'r')
          ],
          [
            'name' => 'name',
            'contents' => $file->getFilename()
          ],
        ]
      ]);

      // @todo is there a nicer way?
      $response = json_decode($file_post->getBody()->getContents());

    } catch (\Exception $e) {

      \Drupal::logger('Clam AV')->warning('Request for ClamAV service failed for file @file, error @error.', ['@file' => $file->getFilename(), '@error' => $e->getMessage()]);

      return $result;

    }

    // Check for any viruses detected.
    if (isset($response->file->status)) {
      $result = $response->file->status == 'OK' ? Scanner::FILE_IS_CLEAN : Scanner::FILE_IS_INFECTED;

      if (isset($response->file->foundViruses)) {
        $this->_virus_name = current($response->file->foundViruses->stream);
      }
    }
    else {
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

    try {

      $request = $this->_httpclient->get($this->_endpoint);

      if ($json = json_decode($request->getBody())) {
        return isset($json->version) ?: 'unknown';
      }

    }
    catch (\Exception $e) {
      \Drupal::logger('Clam AV')->warning('Unable to connect to ClamAV REST Endpoint @endpoint. @error', ['@endpoint' => $this->_endpoint, '@error' => $e->getMessage()]);
      return 'N/A';
    }

  }

}
