'''
All of the interactions with the keyczar lib are managed here
'''
# Import python libs
import os
import json
# Import keyczar libs
from keyczar import keyczart
from keyczar import keyczar
from keyczar import keyinfo


class Priv(object):
    '''
    Generate a private crypter object
    '''
    def __init__(self, name, pki_dir):
        self.name = name
        self.pki_dir = pki_dir
        self.priv_loc = os.path.join(self.pki_dir, self.name)
        self.pub_loc = os.path.join(self.pki_dir, self.name, 'pub')
        self.crypter = self.__crypter()
        self.pub = self.__pub_str()

    def __crypter(self):
        ''' 
        If the requested crypter directory/key is not present generate the keypair
        ''' 
        try:
            crypter = keyczar.Crypter.Read(self.priv_loc)
        except Exception:
            if not os.path.isdir(self.priv_loc):
                os.makedirs(self.priv_loc) 
            keyczart.Create(self.priv_loc, self.name, keyinfo.DECRYPT_AND_ENCRYPT, 'asymmetric')
            keyczart.main(
                    ['addkey', '--location={0}'.format(self.priv_loc), '--status=primary']
                    )
            crypter = keyczar.Crypter.Read(self.priv_loc)
        
        return crypter

    def __pub(self):
        '''
        Return the public key data in a dict with keys meta and 1
        '''
        def read_pub():
            ret = {}
            for fn_ in os.listdir(self.pub_loc):
                path = os.path.join(self.pub_loc, fn_)
                ret[fn_] = json.loadpath(path)
            return ret
        try:
            return read_pub()
        except Exception:
            if not os.path.isdir(self.pub_loc):
                os.makedirs(self.pub_loc)
            keyczart.PubKey(self.priv_loc, self.pub_loc)
            return read_pub()
