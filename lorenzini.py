#!/usr/bin/env python3

import json
import sys
import urllib.parse
import yaml


class LorenziniClient:

    def __init__(self, pcap_file, require_infos_file='require_infos.yml'):
        pcap_file = open(pcap_file).read()
        self.packets = json.loads(pcap_file)
        self.http_request_frames = {}
        self.http_response_frames = {}
        self.require_frame_infos = []
        self.require_http_request_infos = []
        self.require_http_response_infos = []
                
        self._load_require_infos(require_infos_file)
        self.header = self.require_frame_infos + self.require_http_request_infos + self.require_http_response_infos
        
        self._split_http_request_and_response()

    def _load_require_infos(self, require_infos_file):
        with open(require_infos_file) as f:
            f = f.read()
            j = yaml.load(f)
            self.require_frame_infos = j['require_infos']['frame']
            self.require_http_request_infos = j['require_infos']['http_request']
            self.require_http_response_infos = j['require_infos']['http_response']

    def _split_http_request_and_response(self):
        '''
        HTTPパケットをリクエストとレスポンス別に分類して、それぞれの配列にします。
        '''
        for packet in self.packets:
            frame_number = int(packet['_source']['layers']['frame']['frame.number'])
            try:
                if 'http.request' in list(packet['_source']['layers']['http'].keys()):
                    self.http_request_frames[frame_number] = packet
                elif 'http.response' in list(packet['_source']['layers']['http'].keys()):
                    self.http_response_frames[frame_number] = packet
            except KeyError:
                print(f'[x]KeyError occurred. frame_number: {frame_number}')

    def enumerate_http_pairs(self):
        '''
        HTTPのリクエストとレスポンスを対応付けて、必要な情報を含んだ辞書の配列を作ります
        '''
        ret = []

        for frame in list(self.http_request_frames.values()):
            layers = frame['_source']['layers']
            frame = layers['frame']
            frame_number = frame['frame.number']
            frame_infos = self._get_frame_infos(frame)

            http_request = layers['http']
            http_request_infos = self._get_http_request_infos(http_request)
            
            try:
                response_frame_number = int(http_request['http.response_in'])
            except KeyError:
                http_response_infos = self._get_http_response_infos(None)
            else:
                http_response = self.http_response_frames[response_frame_number]['_source']['layers']['http']
                http_response_infos = self._get_http_response_infos(http_response)

            ret.append(
                list(frame_infos.values()) + 
                list(http_request_infos.values()) + 
                list(http_response_infos.values())
            )

        return ret

    def _get_frame_infos(self, frame):
        '''
        self.require_frame_infoに含まれているフレーム情報を取得しdictとして返します。
        '''
        ret = {}
        for name in self.require_frame_infos:
            ret[name] = frame[name]

        return ret

    def _get_http_request_infos(self, http_request):
        infos_in_request_line = [
            'http.request.method',
            'http.request.uri',
            'http.request.version'
        ]

        request_line = list(http_request.keys())[0]
        request_line_info = http_request[request_line]
        ret = {}

        for name in self.require_http_request_infos:
            if name in infos_in_request_line:
                ret[name] = urllib.parse.unquote(request_line_info[name])
            else:
                try:
                    ret[name] = urllib.parse.unquote(http_request[name])
                except KeyError:
                    ret[name] = '--None--'

        return ret

    def _get_http_response_infos(self, http_response):
        infos_in_response_line = [
            'http.response.code',
            'http.response.code.desc',
            'http.response.version'
        ]
        ret = {}

        if http_response is None:
            for name in self.require_http_response_infos:
                ret[name] = '--None--'
        else:
            response_line = list(http_response.keys())[0]
            response_line_info = http_response[response_line]

            for name in self.require_http_response_infos:
                if name in infos_in_response_line:
                    ret[name] = urllib.parse.unquote(response_line_info[name])
                else:
                    ret[name] = urllib.parse.unquote(http_response[name])

        return ret

    def output_xsv(self, sep):
        infos = self.enumerate_http_pairs()
        infos.insert(0, self.header)
        for info in infos:
            print(sep.join(info))


if __name__ == '__main__':
    pcap_file = sys.argv[1]
    try:
        sep = sys.argv[2]
    except IndexError:
        sep = ','

    lorenzini = LorenziniClient(pcap_file)
    lorenzini.output_xsv(sep=sep)

