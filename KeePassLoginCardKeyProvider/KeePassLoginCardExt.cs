using KeePass.Plugins;

namespace KeePassLoginCard
{
    public sealed class KeePassLoginCardExt : Plugin
    {
        private IPluginHost _host = null;
        private LoginCardKeyProvider _prov = new LoginCardKeyProvider();

        public override bool Initialize(IPluginHost host)
        {
            _host = host;

            _host.KeyProviderPool.Add(_prov);
            return true;
        }

        public override void Terminate()
        {
            _host.KeyProviderPool.Remove(_prov);
        }
    }
}