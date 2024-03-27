use alloc::rc::Rc;
use ark_bn254::Fr;
use plonk_hashing::hasher::{
    FieldHasherGenerator, NativePlonkSpecRef, PlonkSpecRef, PoseidonConstants, PoseidonRef,
};

use crate::poseidon::{parse_matrix, parse_vec};

const FULL_ROUNDS: usize = 8;
const PARTIAL_ROUNDS: usize = 56;
const WIDTH: usize = 4;

const ROUND_CONSTANTS: &[&str] = &[
    "062C6ACA1E92C46C6020CFC8AD80661855C9434464AB4FF3335151D0F35F9021",
    "14EEABA2213BF28F15EAE1A8164FBEFB00BBCDD4B7ECBE747FA7109A34BD5C49",
    "296A2D7C793283F53BF61656E498B02828728ADF20FF0B3398C4CBA57E9630F8",
    "1AB075C41D0CC6BB5EF5529EF7285551E83F7C7C6107EDB3CE89A914D14B4544",
    "2BCD55844D9C1835DFE90057D9F7E939F0668BE5D84105F6516481370E4EEB6D",
    "15FBCB4AA2B8BA7625E7A0DA6644FCC82982F40EC86D905DAC78FA0D20431E3A",
    "0FEC3CBB2DCF7505F07505EAC17BDAAA1F3CE0686700256D0EAB2EB1252894FA",
    "2EBB18631151593143043A675CD48B43045F3B0691530426D3B8EC378A7E5DDA",
    "29256595D1DAF032C876EA484FD59FF5D2AFD3B9E3371E620046B511F89FA16E",
    "11F2C85C8341A8B5D6A0AE5C6D23860EBDE99C4D06B22C1B0EA25B03BA2663D0",
    "0223378DE1965135563C66C150EB5FD6C53F587E2315891908BAC7184BF578FA",
    "01775C43F3D8B33CD4A8C3698184574673DE96342FA21EFE4D01D5C73B753014",
    "247762988996B9DBA33D1EAABF03623FCFA96746FDB8A1C54EC8CAAE42992276",
    "1914ACC4486A97E2CA3A0FBDC7D5D09BD8313CF5C38E9AB5EF7BD19A4AC10EC3",
    "230AFE858D2BF91B42329DCCD88A25A9D4BA966E14419520B9AEF951DE943862",
    "046ED2E4ED42FFED58893EEDF7975E990949483210B12D7AAD6CB377E5186DD2",
    "1E95C3114538053B8769901F7FB143DEDF9C59BEDAD62E2851A18F4EE0C5F14C",
    "00E39CD8F12A7685EDE95961E9C0CD821E0F5BC5F7C24FF53BB38854CC179214",
    "22A48D1EBC56B76C91F5C91DBCB176937BE38991D887598285D1B87B6987BD76",
    "172AD173889FEA3543994D23756E464708AB4E3FFD5B523D40A2DF13CBB0EE96",
    "2617BB0620340EF42E305956F29970241A45959615260FC07F9829C254923666",
    "23BEAC684D68B3C310A9BA2642E6DBF66E9BDCD3E40B0C047990AB7C368AAC11",
    "0411E23D97C9DCB808B8CE71D7BAA99AA95F8FCC08529699E55F751D79DD24E3",
    "273A3A586619A58E3E96B32B5CDC520880546DB015B8777E11E6F7450439D0EE",
    "2B6714F91D7849D1025FFA954F57569C5A8838AB75B134A1D30B09FAAE282EFB",
    "243B328323CDBB3C7CDAEEB152ADEE94276DA72C7CD8A35E99ADE7868892CEA0",
    "26A972F999B68E97ACE9A4EEC0F943910103030B29CEFA3F7BE863DD1707F968",
    "2ADF1BB322498C052C54B8FA10F403E0FB9DCB76158431831AC9376DEF9C740A",
    "23310B7EF40C0BABB2A2808664E3FDC7205751D1DDEC0A5A76B4ED236DFE68DD",
    "148474F9969233D119BAE3EE957038D65A5EA6AFAAA6CD499D65BBFFE3ED05CB",
    "2ED449CD4C9F6E562E92AE737FA0733C67BE1EE11BEBFA3FE048803EBCE8F18D",
    "269DA38B955C8C6B6BB58695A570E6A34B61769E87251681CC966FCA9D2DDEA6",
    "277A69C44437B46607D509F1879E92C6584D1FF4D47B6891C34C9F6AFCF61810",
    "2AC73DB02A1461367C8044BCD02D965BEF18B65ADF04BE5A60786DB393176727",
    "23AD5251099C88CDBC3C2471F3B846C05938A6BBBB76DD2DD245A9BF0B6B3E1F",
    "2E4536EB7EC62C78FB9DB28766325BB0885BA6CC299B5CB680EF9C7F11ADD7B0",
    "082D67B47527C7CCDB2DEC59D922DC693BFAC2F92D6FF1F8753B3F6702106243",
    "2F6787037CB13533657D7DED7377ECD3BD652C827959D272B9C82893C2A755FB",
    "0714C33AFB146987A311230EFD6695758E23DDD016354AD17CAF46FC183F53C4",
    "2E190AD59FB275F062B080A1686F0F60D1EF8B827E233D5961AB220BB23B1C2A",
    "21559D269992AE057BDC4324B93226D08F7886B5F5134D3E1F7E49ECA9E16394",
    "1CF2A4D57999D721B74F11FDB6CE5820145245B8A2C5599284F784A8F6719E46",
    "0E1AE25FCFF96304A4FB6207644072C211C7BEB0CA90AEBC899C53A876016609",
    "1584EC5473CC0733F3ACC56CFAA968300FC07DE5E886B3BD1D14A92E77C7ABF7",
    "0A7BC3B154447D511F04871265B8062CFA273C092A9E2F62E3C2BBFB112CF7FE",
    "28747836ECD2BE5D40B988CEA79A8857C3CAB62A95AE9171366B72F7DEA939F4",
    "23BE307EE51E97C1E2937DB1830215A5EAC33D725738364ADBF3D81DC7C2D30A",
    "181DEF07947F96DB72FB5E362263F9C8C8B69B4674F5211B9507CBB7B873831F",
    "0F8D21A7C818B1F4B9F83A9D65F8F7F55F5C5EB4593ECF684221917B3E39B588",
    "05295519EF59D19282820564C1B82B983481B2A96CF7DD2247D063DF441E6BA4",
    "05A3CD2F51447738A062FD93A8272B5289315B1AAA64413ABDC40D68B7130AD2",
    "11492A233946829DCF370D93E21333B3AF3C50B0F383008DF2C310FE3B6FC474",
    "101CCFEDAAAFE9BD31BB88976FD9F03A90E0D8C1CCE55E9046D2511C6DFECCB8",
    "0A152C325BE5B2772785A2F728EB20CEC5B22436EEAFDBB381E045C6A62AB938",
    "15FA1605B2FF2E7E817801D194D2F60C569549EBBC4BB59AD8343E2B4C5944EA",
    "2998881E818B9809E8A5C8C0117B1F7AC8E9BFB2F0BC517BEB0D1F21B08B3548",
    "26D233C6367E02F595AA143EBB7DAC96784A98C5A3BE6339E8D4E321566EB932",
    "23D5C7234F84B69C425754BCCF3446911F57715C0F32C4045AE12400743F178F",
    "0C3E111A0162923B3274576342AA9DDC97724B744065658ED192020E175D79D3",
    "04E84EB21CBF0E9AC7FBA9F16EC322E651455B8D9E2C9C7A7FED1AD2D4CA41D9",
    "177EAE242329A90B9428BD2A770B79DDBE20C9BE111B000E12E8DA1587AA098A",
    "1DFD07AF57D83E452156D2395917954F63112B1CF08C65B5DC46060284609CBB",
    "0C93CC22811728871FFEE73031DDE764F68859060076A84C165F32BD80B144DE",
    "192BA9406DD09F462A2BDE34FF0C3BA11D9BE34093826BCC5AA29BEF6BAF4358",
    "1BA544393F910C5ED2A958703D4DB259B7BA38E00ADED367A4C8A668672FC223",
    "130D3C3AB75A36F92A4D21C43CF05DE1F22DC6522C744AEB1261567262C0FF52",
    "2EB942F851531EF85BAD6655BE277CF999B54B92E06D203E510FE1DC6A55B907",
    "136AAED22FC112F0FEE586D7CF0C6411D45EEB05710726A4C83B622D24E9BE3A",
    "12A19EA10014C706F847311AD4FD2C4604FCF5B8512ECC0CD406AE03D9C2637B",
    "1B96B73416E277AA0937D83C2302E1FB814049A5391EEA4440BA5DB482992D1C",
    "0CFE78B62E6E92E1598B89BA9CDC8142F0BDC8C2E7B044532710DB5695EC5191",
    "0C57AAED1EBDD8C620A331358EEC7033A7A9131BE98C0AB89C14E8F83844B07D",
    "0155E1F2717D6781A983D590B4FDC9C49AC0C38941C126F374DE635FD2755F8F",
    "2F8C35FAC154C165E591E13738C6BA6E5386CD5DF1C2E6D3E26EDF5D6C7EDB7C",
    "26EB32752B9BA4FCEA44BC87EACA32BD5519B5907A6B23E0A7A22B7D11E15CEF",
    "1B21E5EAB111193FBF5417CAE28E4737A5F1234C229E1AD5A74304086C9827CF",
    "111DC2C678FB55005223E774DD129E7764608E8138FBEB1CE5DC8A6979A924A0",
    "3024A27AE2644FB248A6BA362F771517DA30EC6C46F61F27A63CA4C59FF8E830",
    "018429BEEFF6C5E2723B1766E152E2F27F59B1B9E71D64FB17FD40E024E75B03",
    "0E5A747C762F153DA09B482266454815B8E5083A8D0B59F7F9311DDD79041395",
    "079D637718B241CC645289F8D25AC5952505ACC57D1D7E4FFEFD04813B34BBFA",
    "0070074FB2D6A94E73ECA8CD086C36431EB9D5ADB3DC7B3C70EE0B118C225458",
    "234DC6197E3DCA9FD5E86AC3CB64A2BB0844D066DCA20401BF8CE948F96AC82B",
    "0225B5A421A0705E7D9DB0992862078B88766B068B7FB5BEC246BE1D830DFD57",
    "0908CDB99EFA659AF9D2B7E91325E2339F429483F78E803941E4354260B97554",
    "0AC72765A8C8304270058039D6C7F10B632C834473CCB5D61C9B992E41AB4DAB",
    "1D1CCD8429EA10853A07A29C7432DB4970A024FBC6B60A2B86B409A1C4C9EA7B",
    "11CCF1FBE38BDCB6918C67855A3C075EFDC43E26FF61ABECC2DBF5AD6E996199",
    "2A43E4C56B73C897F858C00B1F8744444C6B5355A8DB4D18F816AE9A9526A897",
    "2412F617FD006FC2DD379A160B06F0389BAF81201FD6A84DA617F6BD93903B58",
    "1756030EB27731733EC831C934FDEB2345A96F1BD67D2811739E496F31C42140",
    "03B715DE5B3F4C3BD38FAF77A5D0C09939947E4AB59E4A85CE1AEC29F4637B08",
    "178545B27DD6BD53D128DB98747E80B8718218D238DC754BC8DF8BEA6C3D79CC",
    "107079AA6ABEE32CB03F749E6F83D5CDC47E2E91E82C797A78C8B28A71416B4E",
    "04082A3658D386C5FA20A4C8CD6E73503E9420C68FD00B83398D2F488A44D581",
    "2270508F9D6DADCB0E02F120FDFE38487B5B0F69BB243ED464C3E002798F2265",
    "046F0E252500552CF8FC3E58A39E84D999AB4836CE57585E902AFB24F847D61C",
    "1EA9FABF55D55D84323CA3DD16A8A6C53800615CE67B601845C211F5E3FAA342",
    "24F4F75614B06CE4C6AAEA5B1002FDB71F284DAA807AFDCDA58E0B70224DDB03",
    "0594A498BACD7B3212014E1901F6219FF89C7CCEC2280584BD53D36F2E49A9C3",
    "2CE8DA8FE21876EF86DCECAD0FFE9542229309FEAC2DAE2AF6E269A9901AED80",
    "2B2E89DF9958A60F7DB125E85FD3DA7184428DF6C7C41075D75FC64002810592",
    "25C0D5214CD33BAF7CC873F8E47CC5B641D8047B232BCEF84D29EFBED4927668",
    "02533B700F34A3BC7F3C96796BC4FBF1DC62AEB77EA374A942C318FE2093DD35",
    "0BB3D5FD1227E5C53A06F4AD7BA2D02415BA78F0CF22CB2AC965F50FF2FBD437",
    "24DCF69AB9CA6D4C06488D6968326B452F6F04F286E5FFE6321815A9AF37FCC3",
    "26B198385667CE7826167AE55663E16B42E5748F8AA74DC1C7FC89FDF8DE91B1",
    "0C5583A503417DA5D4585429CA76CD0B800FB078DC17825FCABBDC9403B2D4AA",
    "075637751CA0A4494B8157EE6D419EDF9EDBA3644CA2AF11FD82F80B5EC5039D",
    "15351656361B41566C2D3AB128EBBBD9A7299EADA99E8D7F1A96D4252D78AFD7",
    "005F4A8F76D7E3C6401EACA534049F29ACCC4BC35DA4DE533D3677861B359573",
    "0496A7D05C24DDB735E5B20E40A96F680A33C237F0CCA9F487A05A2753428D49",
    "0FE8F4E256E63F6B6992668EB6A8F406803BF47C320238C21C35387AC1717607",
    "0B7C7AEABA7F19B9E535A12520FA2D6396F81394A815B1D495BCDA16A43D5767",
    "1A5FE03AF259060E72B9D223DDDF43BB539239899EB450BFCFFC8F28C0D63EED",
    "2D786315D1DC2036E359E13C2916AA511984225C5ADE687781D19EF752E25B8C",
    "05EE2AA110120D1746E7340304A5BE1B34F4FF48E276B43087E02F9903DD40F5",
    "16F2AA9F5E48F9F81B1D4B9833553C7C64E39CB3168E3EDA6A63D5ED7405216D",
    "1C9DF34CA603281855365C200BF42A44B6DEF0961127BC0F66F3D9C089985637",
    "27FF728612F725944265A7B3E485254540DFB6C9CFB1301CF5D8A02462FAB1CB",
    "134D27ACDB0BD58812ECCB8F018F1C5CD3ED7485FB512238488A13D9D573EF31",
    "259168C10603258AC07D4FC147A81C57338A31FAC9C2FA85A19977599CB8BEAD",
    "035DD698A8313AC807769ECE0A30A4F8ED161039B528BD646F3D808199698912",
    "28CC0F781024F67048D030852315975B5192617C01465BE524A0AC01BCD2EE31",
    "052811D6EC990B181FE4432A2DC49F24CE9CD76D27596F2640ECF31FE58F6D5A",
    "07C8C29D0445597B3B85B465FAFC28832BB31A77E28D965C1790CE0DF4E22008",
    "04F579792AA7E217F44FC1212022D398FE77F3C771BE647AEA033DBE09A95D74",
    "030C8731E751707E06847B5EA2E05E0A868F0C6E55800CE57965B28E7B4D6E1C",
    "178F1A8728A1205D8122E0A8FEE97C1F8E51F39634CB7E6A45C0A985E31683C9",
    "16B6008032B6F34B8ACA4AAADF35F14C9652D063AA5027095863E44C40F397F5",
    "1E4EEF2C593985C847AC81F2350CD52D51F6154A24662BBB991E7F8BB7B74EAE",
    "281A1707A55DCEA809259B7401226657604679D594D1DD5D81615F234C82F7D8",
    "016B594EADC674F42202A52F2EA8E66B039871F14229BD30380BD9CA01398E62",
    "1B317E817D873133F4210B144AA4F6F2DD92AF4D5C661DA897AE6E03308F404B",
    "1908A8FE3D25CCD5402A336DB3183D5E06CBEFFC06AC60AAAFA4B47C7E725094",
    "266962E4A5AF371338C5E8CC772F98DBA341A465D58E5CE7BE1B4C47D9662496",
    "21746CCB8A1669A753BEBDA71AFCF98F261F918AC3A5938130771549416D2B33",
    "19AEBF77595A021DE63E7706E91DB942B7FD09C25104A09049014A37AFDB5812",
    "22603CC38BB21AF4777EC442679BF688315FB45A92765B4375293D840FB11996",
    "0D35AE23BC87037913A7C4383E3EB3BE0BAD7582984B8A7B515990D89EF0F245",
    "1C1C697910A8E41C88C1679C3D92A3963B4FC6A47B24FCED2B940AC95F4A408D",
    "1CA9E35686BF4FBE4A64D4F898518F13D9EFD237CF91B896C32A3BFF7C80BEE6",
    "14CB81D1B894187D964EDE691EDF60B0A445E608764DD100F15A2C5B3A4E8AFD",
    "2A6C8BCB6F72DF74CDEF9C1B98879A9179D0245DC434170A439DAE87F9DEE41A",
    "0A4C43AEEA2D4178199693365B4B05F56E6E314E243C5A1FC2B80588655D158E",
    "1BDBFB77EC520369972F8EB51B9F8187B25F354C29E0D7DFFE27712B7CD856AA",
    "1AC400527065DE5C14A262470F77BAB968A5AD2FBE111E6B0B2680A8F189A1C0",
    "0526FD130C672B712B11FEE5DA81926447C5D488FD5E1233D1DD376414383674",
    "12F8D1FAB8A19B34C88ABFE247A44AFA6BA9EE834A07F4E1E32674FE313E14C1",
    "2BF98D5E6DE258410C8362CF2983D3FAD0998C40E11443F1CC0F40232E2D3705",
    "0BC8ABB18DDB7CEDE29B2D8DCEFBF4C4B9BFF1D84E902F985C31125644CA10BE",
    "08C7C7EC07CED70D6B1B8F30BC815B8BE03262C04EFC8819EA0E5ED0DA69FBEC",
    "25980123CFF50082A4FDCBE51A203871B3BA46696BA933E4A89E7B7CA79A7F3E",
    "207A75EFFC6F74F4BDCC5D06F48D4CA55563F1C7418AB771E2EEB0DED0937B0F",
    "104701EA21023FB68B695FE87AA3AF01DB074B15125A6A570C77FB8140830F7E",
    "20005561EB500A83B657B2C32808A25E05CB68BF7E97C11375DEA0D7D0BE78EC",
    "1F03A4F63DF6AC8C2C9125EAE947E5D5D1B663DBC4A00556EE847AA21165C288",
    "1D2171F8093461111ED738AFEC038BA015864C4D66D480560DF9B6794F075610",
    "08FFBA196691330A32A56CFC9C536EC50E17DA8A4303AC10E926670F863FE90F",
    "02AB60FBB5DE041572017587059D91C0CD9654B4FEE0DF43EAE0FDEB7BDCF8DC",
    "166E6AD289D9B5A412EEF66A22901C902093C9DE42FD9653B911487C4C3F2EFA",
    "2D4CE67AD7FC6E1B9282A994381BD283F37730FCAA8D76DED33890B8593FA48A",
    "208E3B25ECC461666DCBDF4B6FC31DC2401A5AA0300131AC146289084E45F797",
    "2F0025FDDE0FC92A153372B46BB8A6F075AFD9930AB352C8BAC0B932C15A2D33",
    "1585C575C253FC0E2EADD6DBB3E0DC6D85012209A32E1C6D88530A251DE28786",
    "1C41FCD6A2E52A7FE8AE67FE520B7FB826B20CED5873312DA249FA30C8BD5DCC",
    "13C31471DE3D2B315BDC058AF41241A6BFADD0A579D471CCB3BA32E7BD38D7E3",
    "096740BD61BB991DD3CEEA397EFD122E86260907C51AC14622381553FC1840AB",
    "10672737C12B2EC496FC158D7A053C278EA47780AE0C7E24200E2804BF94503C",
    "0AACC473C04C002163ED589C8A7DBEC5660A553665E2E2991F91C85318582B6D",
    "0D7EE3A8F23139DD275EDF874874ED653EE7E2A741FE253756F6C3DD17FF990E",
    "15AAE7D2D87C01FA8EDB9859DE8FEFB9CDE57528F4C54ACCF8D0389B2FB9C795",
    "00D4C4AA2DC53DD9B2E66FE8E5E761D222C152A13416976EA87403A8E5DB0D66",
    "27BA19D17DA6AB3CB8CF90987E876331880E51FA512BB4DF331886D1DF952A6E",
    "171D9B3603F0256328654D0D43DEFD3D65FC9664ADC0A84EFD531A590E7D9786",
    "01500B0E935C638B959F0AD962A46DAC1BE52A2E28DB4F9FE9E59426F3D83A91",
    "1AE1619F0C8D5BF857C53202E4C506C78E8977DCDB01A9D21C5EDE20AA393DDF",
    "139B58E89CB51FF5B2B862FBD33BC0EC96048DDD4D09CDB96DFE71B23EBEE9F9",
    "1DA6B9818C0CF21C320FAF51E2CC29BBA405179D484C9400D928F26B62955B4A",
    "2587321571877373FF6AB917E30F6ED72D78333C85D75EB004BF0D489FEF0948",
    "042181A77EB6F3AE944D0F08CCF2867EC4A6F47FCACC47676E0AC77580A4FB62",
    "012CF24D3C45F9AC2D7AA214ABE8AF11410520EF53B5182F3747C116C762BB04",
    "2C9466AA79795F451D7B2D569CAEEB19E0E15C1B8D0DEE461E1BC756DFDE7A79",
    "2D408B4B4533C3EEDF37FA79E725AE713E6F0039CC719B03321BE66A0EC603C2",
    "1FC41D446981DABA5ECB2ECE24DDA3DC5BA392E0333138EA121E59C46AC29CF3",
    "06AA082B7541F77640A290468A9E82EE39079D8206AB0841D8D58E88BA2D9189",
    "15EF3B9D50F377477F095CC3CD03B2989781689105064B64A0087638C64EBE84",
    "0A90E6B5FAB4037FBECF2C80B643FC2A5B8E99CD95A27192604D8D7A8CCABCF9",
    "0DB125FD71767A993DD7EC4C9D38AA48C237E022590BE3544AC83BFC69F92A22",
    "06037674E7B173E2D24DE01AA4CF094FD01E9FDD106397FD02EB8F37348DA73D",
    "1841E8F9AC8AB08085CC8C16E730BA837AFD49F3B0F9DB20A45AD41A79B267D1",
    "25725A5F311630F6FA8324445E0087CD642869CB57C9F8261BB62C9FD2A56980",
    "095DC3C5ED6F713C97999053186B0009B1C659387B2B332860E33925CBEF5388",
    "0D9ABAD437B44000A41D240498121FF1112E19C3434ABB708951319361E867E6",
    "07EF67B5CD2B35F0F238581A46D9C6277139331D81707DCE5444FD1A72CD93E4",
    "07DD79C1D9146721ECA123FE5F8C93808B5774593273A77A4C154EE3653C4DEA",
    "188194AEB971C87F98AD768E0FE218C7179E65609C851328DC300C31797A969B",
    "12B0362617138BF98482F29BD4DB68465B48A3251A105895E09BE002897521A1",
    "2C3939A8EF0739B2E94B0DB5B32188F00686E3A8D229489F6B05A7537DAA7330",
    "30307E22DE5DFDA2E5810AA4266C1584FCA3FD13975CEAA107E20AF9C0C15E13",
    "0D1AB46F67E8DB9AEEA6F0F5515706FFCEB6064203CC39ED8630D3C8B3D510AE",
    "1D2FB74BBEB806329916D908BBEC6089CEECE8B94237FC6B241773F3FF529D13",
    "19318096F75DA85A95E9A5A3E2BAFC37E6DC45DA570E3ED175EACCD3A919BEC9",
    "14D17228A4FFBC78F9E66019E6E6898870D5BFCE021064F8405C7B286D58C937",
    "026A2DF77302E1A105CCD2CA8667A378EE50AC98D11AD081DEEDC14235F3FAC6",
    "18CE00846AFF15EEC9133020D921EBA4E1EE9D8FFD6150FFE69A70D15DD1B7AC",
    "0C879478563DC8C68A484BA9A0BC4A72A650494E5AF9A35C7871C94DE1E2B4A2",
    "2B6FE209C5570091E8633BE911725EC22716726A2C9CC566F050779225C3812F",
    "21EB176282351522403B995ACD9C1CA025950109386333D89F79CC10AA989B2E",
    "234C773095E28E6B12C67C2F7872E88DC5469762B407A9CC9471CFB4BD259B2D",
    "2283FCD1EB4741702A7976FC92ABCDCBA9E0869732D55BE3664FC3EE03B80936",
    "1CF0E5100BFCF33073DB928516A7F552670A6AE65605974B2A1C4517790ED604",
    "2A13F902CDB035F0891599636116AF326307C2406E04EE43143138557CBD1C11",
    "16DC2D9CFE66518ED89641FEA98DC84DBC6BF1B84D84C24D5E0AB5574EDDA2F3",
    "23FD820A6B29DDF80DF7ECB1EE96AC8F014E87113973261EA0A69ED244282166",
    "02231D66A1B80840512F3880D15787974C0F6DF853F8FDB8729E1B1BCD73A176",
    "113DD55E39CDC1DA330D4A620DE37443FC359023527D419FDDE67C8C51CEB38D",
    "0AEDD2B8F75061B641F975AA379906C682F0B5B79042E9CC499CA5EB3CEA0852",
    "0BB987D50E4CBDACEE349749A05C0DFDA0CBFE1E5F222BBD481ECC56CE0DECF4",
    "250767B9F4005226ECAAB5EA8967FBE88557FC5B49E49BFBFEF590B6B070A0CC",
    "1E925E995131486A437D19EA2B45D40ABDC598D42512CDA96BD49114D857DBC8",
    "28114A1800EF14CB7ABB50BF85FA9204A7B1A857640DB27BEEE183BAA02744C3",
    "07BE8C7EEB81D81C444C7D9D0711B293C5318186A35EBE28AB6F498B6B130CED",
    "24DF3D8A18DEFC5BB91DA2428FE23E1CFA8FCFD02FD7AD4DE4877DD1546D4CE0",
    "00AA6D567DDC5B34B5C7FF285FBF87D5E8472583915AF63BDB031B30D284FD23",
    "11290AF7A614E4A9353687EF1EF8BBF94732C14564A12A1516351209B0048755",
    "19B44A049DD76E71B91FB34EE381B970219F2A7C00F1950BDCD250F43F1261FF",
    "230512420CFA2E804C2D3F84F679C6AF342BEFE4FA432CE2311F97CA505EBE30",
    "13E686E00E752080AEDE35A9882ACEF3C542F200544F7D3E6DC34A9DE0663510",
    "246F2A9655A503457E7A33560307D79E0A70DC6377B27C1588ACAF6FAF56D707",
    "038657413E7230CF9F6850398C525F5BC7E0526ADDCD34C87120BE083A31DCB6",
    "12756FBB1BE74A0FB53F02E2B18F42B69AE6BB118CB86C1F038D8AD886DA9BBB",
    "0F75023A1DE10320C5C29A09BD9DCE6EF50457E6CA8C2C1072BB34FC76CA81FC",
    "25FE7D315D41922A741464D26E3BD47DAE7ED62AAEB39F105873DCD3BC1106D7",
    "1D1D8854AC4FCC08B92AA935C4E5AE5318F242F5DC01871297EBFBD0CF0EE57B",
    "0B9FDA3453F383D1E8601FBCD6505BFBE776910D35EE649EAA2A26901FA50FEB",
    "12CFD4D9401A0E6E680C5FF57298B78B4F0EB4B548B5500CF6E967615AECC962",
    "244F9409CA616BF48BF2ECC1FF0FB69AC845E7F93B385EF74DA105575886D809",
    "1933CD0D646B9FF51482ACADE913EAB08B645C796EB7CF977BEE5A9D0CE9325B",
    "1085B5961D9550CB7751BC5E94DBA486EA43E6DC51FBD2BA255BFFDBEBA90903",
    "1E72C3F0A6A08C47F76FAF002AAB7422086CB9917B83B3708D35AD8A6DEDCECB",
    "1700157E20417BF8ECDE648B960E8D4919D56E19E62772B18259B15AABEC85E7",
    "1DFAC3414E9E4A6AAB2DADB3E66229A0A5846C1153A8CCBB28A0ABA1D187BD98",
    "1B2EA16EAF3E7D6194703BB60883FC2CEEF7F26EE6DBBF4D3035DCBC2DB571B2",
    "0A4EB759D6CBB05B65048CF3B5479771F2174E139C0E46483226E1A040C8596B",
    "0833B5357FCAFE0B1D8520E315BAD4CF10A33ECEB9F6D76A61D78D19B8AC2C31",
    "2C3C184455EE8F238DB25F36F8E53441ECF65DBB8890CE6B5DC1BEC397603299",
    "1C3FFE2CE392F9583AF47D9A5CEE2285A705C7CB08C75DC48E787D0C3FD159F7",
    "21B9AF9673B71CBFAA2B0EF524AF2FD93C542FCEDAB07933633645191E2577B8",
    "229350D44EB6F2EC6371E1490277D7935E099DD8E279085B8CD7AC1DC605310D",
    "2761288D6F4AC17AB6862A30A4B60517F952D4428D62F52D389DDBC347EFE82F",
    "1B03EAD6D18DE2EB94F830C4EBAF8483626251255FD7280268F2E5ADBCB641A3",
    "29C784FFADD205EDCB619E26DF39FA73A26662904FB4C5E8614CB60A76DBA7F0",
    "263B97D88ACD3A1BF4A71B3117BF0ED273251A344402F3293FE752C53AD4BD0D",
    "303D4A3CA16229FB2DA6509F4D9C6A4766879CDFF13D5FD7F60CB15DB997D6B1",
    "234BE29D8BEC9C5C813CA39B0B8F9A7650E128DB4BF082BD03AB0B1145E95CD7",
];

const MDS_MATRIX: &[&[&str]] = &[
    &[
        "244B3AD628E5381F4A3C3448E1210245DE26EE365B4B146CF2E9782EF4000001",
        "135B52945A13D9AA49B9B57C33CD568BA9AE5CE9CA4A2D06E7F3FBD4C6666667",
        "285396B510FEB022C442E4C2C1411EF84C2B4191BAC53323B891A1FB48000001",
        "06E9C21069503B73AC9DC0D0EDEDE80D4EE2D80A5A8834A709B290CBFDB6DB6E",
    ],
    &[
        "135B52945A13D9AA49B9B57C33CD568BA9AE5CE9CA4A2D06E7F3FBD4C6666667",
        "285396B510FEB022C442E4C2C1411EF84C2B4191BAC53323B891A1FB48000001",
        "06E9C21069503B73AC9DC0D0EDEDE80D4EE2D80A5A8834A709B290CBFDB6DB6E",
        "2A57C4A4850B6C2481463CFFB1512D51832D6B3F6A82427F1B65B6E172000001",
    ],
    &[
        "285396B510FEB022C442E4C2C1411EF84C2B4191BAC53323B891A1FB48000001",
        "06E9C21069503B73AC9DC0D0EDEDE80D4EE2D80A5A8834A709B290CBFDB6DB6E",
        "2A57C4A4850B6C2481463CFFB1512D51832D6B3F6A82427F1B65B6E172000001",
        "2B03D3F456650025159CAFBEAC013219EAD8CE794FC1479D91AC688380000001",
    ],
    &[
        "06E9C21069503B73AC9DC0D0EDEDE80D4EE2D80A5A8834A709B290CBFDB6DB6E",
        "2A57C4A4850B6C2481463CFFB1512D51832D6B3F6A82427F1B65B6E172000001",
        "2B03D3F456650025159CAFBEAC013219EAD8CE794FC1479D91AC688380000001",
        "21DFD0839DA2BCEA0104FD995AA7577468F122992201CECC15EAF8B45B333334",
    ],
];

pub type Bn254x4<CS> = PoseidonRef<CS, PlonkSpecRef, Bn254x4Generator, WIDTH>;

pub type Bn254x4Native = PoseidonRef<(), NativePlonkSpecRef<Fr>, Bn254x4Generator, WIDTH>;

#[derive(Debug)]
pub struct Bn254x4Generator;

impl FieldHasherGenerator<Rc<PoseidonConstants<Fr, WIDTH>>> for Bn254x4Generator {
    fn generate() -> Rc<PoseidonConstants<Fr, WIDTH>> {
        Rc::new(
            PoseidonConstants::from_constants(
                FULL_ROUNDS,
                PARTIAL_ROUNDS,
                parse_matrix(MDS_MATRIX).into(),
                parse_vec(ROUND_CONSTANTS),
            )
        )
    }
}