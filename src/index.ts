import {IVaultedKeyProvider, IKeyDerivationArgs, KeyTypes} from 'jolocom-lib/js/vaultedKeyProvider/types';
import {SoftwareKeyProvider} from 'jolocom-lib/js/vaultedKeyProvider/softwareProvider';
import secureElement from 'secure-element-interface';

interface SecureElement {
  init: () => {}
  getRandom: (len: number) => Buffer
  getPublicKey: (index: number) => Buffer
  sign: (key: number, message: Buffer) => Buffer
  verify: (key: number, content: Buffer, signature: Buffer) => boolean
}

export class HardwareKeyProvider implements IVaultedKeyProvider {
  private hardware: SecureElement;

  constructor() {
    
  }

  public getPublicKey(derivationArgs: IKeyDerivationArgs): Buffer {
    switch (derivationArgs.derivationPath) {
      case KeyTypes.jolocomIdentityKey:
        return this.hardware.getPublicKey(0);
      case KeyTypes.ethereumKey:
        return this.hardware.getPublicKey(1);
    }

    throw new Error("Invalid key derivation path");
  }

  public getPrivateKey(derivationArgs: IKeyDerivationArgs): Buffer {
    throw new Error("Private key retreival forbidden");
  }

  public sign(derivationArgs: IKeyDerivationArgs, digest: Buffer): Buffer {
    switch (derivationArgs.derivationPath) {
      case KeyTypes.jolocomIdentityKey:
        return this.hardware.sign(0, digest);
      case KeyTypes.ethereumKey:
        return this.hardware.sign(1, digest);
    }

    throw new Error("Invalid key derivation path");
  }

  public async signDigestable (derivationArgs: IKeyDerivationArgs, toSign: IDigestable): Promise<Buffer> {
    return this.sign(derivationArgs, toSign.digest());
  }
}
