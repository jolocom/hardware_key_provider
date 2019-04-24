import {IVaultedKeyProvider, IKeyDerivationArgs, KeyTypes} from 'jolocom-lib/js/vaultedKeyProvider/types';
import {SoftwareKeyProvider} from 'jolocom-lib/js/vaultedKeyProvider/softwareProvider';
import secureElement from 'secure-element-interface';
import { IDigestable } from 'jolocom-lib/js/linkedDataSignature/types';

interface SecureElement {
  init: () => {}
  getRandom: (len: number) => Buffer
  getPublicKey: (index: number) => Buffer
  sign: (key: number, message: Buffer) => Buffer
  verify: (key: number, content: Buffer, signature: Buffer) => boolean
}

export class HardwareKeyProvider implements IVaultedKeyProvider {
  constructor() {
    secureElement.init();
  }

  public getPublicKey(derivationArgs: IKeyDerivationArgs): Buffer {
  }

  public static getRandom(nr): Buffer {
    return secureElement.getRandom(nr);
  }

  public sign(derivationArgs: IKeyDerivationArgs, digest: Buffer): Buffer {
  }

  public static verify(digest: Buffer, publicKey: Buffer, signature: Buffer): boolean {
  }

  public getPrivateKey(derivationArgs: IKeyDerivationArgs): Buffer {
  }

  public async signDigestable (derivationArgs: IKeyDerivationArgs, toSign: IDigestable): Promise<Buffer> {
    return this.sign(derivationArgs, toSign.digest());
  }

  public static async verifyDigestable(publicKey: Buffer, toVerify: IDigestable): Promise<boolean> {
  }

  private getSVKP(): SoftwareKeyProvider {
    return new SoftwareKeyProvider(secureElement.getPubkey(0), 'password');
  }
}
