const jwt = require("../utils/jwt-util");
const bcrypt = require("bcryptjs");
const { redisClient, getRedisData } = require("../utils/redis");
const userModel = require("../model/userModel");
const categoryModel = require("../model/categoryModel");
const axios = require("axios");
const mailSand = require("../utils/nodemailer");
const azureUtil = require("../utils/azureUtil");
const dotenv = require("dotenv");
const { handleUnSubscribeTopic, subscribeUserToTopic } = require("../../firebase");
const addressModel = require("../model/addressModel");
dotenv.config(); // .env가져오기

const getAuthUrl = (provider) => {
  const redirectUri = process.env[`${provider.toUpperCase()}_REDIRECT_URI`]; // 각 서비스별 리다이렉트 URI
  const clientId = process.env[`${provider.toUpperCase()}_CLIENT_ID`]; // 각 서비스별 클라이언트 ID

  let authUrl = "";

  switch (provider) {
    case "kakao":
      authUrl = `https://kauth.kakao.com/oauth/authorize?response_type=code&client_id=${clientId}&redirect_uri=${redirectUri}`;
      break;
    case "google":
      authUrl = `https://accounts.google.com/o/oauth2/v2/auth?response_type=code&client_id=${clientId}&redirect_uri=${redirectUri}&scope=openid%20email%20profile`;
      break;
    case "apple":
      authUrl = `https://appleid.apple.com/auth/authorize?response_type=code&client_id=${clientId}&redirect_uri=${redirectUri}&scope=email`;
      break;
    // 다른 소셜 로그인 서비스 추가 가능
    default:
      throw new Error("지원되지 않는 소셜 로그인 제공자입니다.");
  }

  return authUrl;
};
// 나이 및 성별 계산 함수
const getGender = (birthdate) => {
  if (!validateBirthdate(birthdate)) return;
  const genderIndicator = parseInt(birthdate[6], 10); // 마지막 자리 성별 판별 번호
  let gender;
  if (genderIndicator === 1 || genderIndicator === 3) {
    gender = "남성";
  } else if (genderIndicator === 2 || genderIndicator === 4) {
    gender = "여성";
  } else {
    gender = null;
  }

  return gender;
};
const getProviderConfig = (provider) => {
  const config = {
    kakao: {
      client_id: process.env.KAKAO_CLIENT_ID,
      client_secret: process.env.KAKAO_CLIENT_SECRET,
      token_url: "https://kauth.kakao.com/oauth/token",
      user_info_url: "https://kapi.kakao.com/v2/user/me",
    },
    google: {
      client_id: process.env.GOOGLE_CLIENT_ID,
      client_secret: process.env.GOOGLE_CLIENT_SECRET,
      token_url: "https://oauth2.googleapis.com/token",
      user_info_url: "https://www.googleapis.com/oauth2/v2/userinfo",
    },
    // apple: {
    //   client_id: process.env.APPLE_CLIENT_ID,
    //   client_secret: process.env.APPLE_CLIENT_SECRET,
    //   token_url: "https://appleid.apple.com/auth/token",
    //   user_info_url: "https://appleid.apple.com/auth/userinfo",
    // },
  };
  return config[provider];
};

// 이메일 인증 코드 가져오기
const getEmailAuthCode = async (email) => {
  return new Promise((resolve, reject) => {
    redisClient.get(`emailAuthCode:${email}`, (err, result) => {
      if (err) {
        reject(err);
      }
      resolve(result); // result에는 이메일 인증 코드가 들어있습니다
    });
  });
};
// 생년월일 유효성 체크
function validateBirthdate(birthdate) {
  // 1. 형식 확인: 7자리 숫자여야 함
  if (!/^\d{7}$/.test(birthdate)) {
    return false;
  }

  // 2. 연도, 월, 일 추출
  const year = parseInt(birthdate.slice(0, 2), 10);
  const month = parseInt(birthdate.slice(2, 4), 10);
  const day = parseInt(birthdate.slice(4, 6), 10);
  const genderIndicator = parseInt(birthdate[6], 10);

  // 3. 날짜 유효성 검사
  if (month < 1 || month > 12) return false;
  if (day < 1 || day > 31) return false;

  // 4. 성별 코드 확인 (1, 2, 3, 4만 유효)
  if (![1, 2, 3, 4].includes(genderIndicator)) {
    return false;
  }

  return true;
}

const getResidentNumberFirstDigit = (birthyear, gender) => {
  const birthCentury = parseInt(birthyear, 10) >= 2000 ? 2000 : 1900;

  if (birthCentury === 1900) {
    return gender === "male" ? "1" : "2";
  } else if (birthCentury === 2000) {
    return gender === "male" ? "3" : "4";
  }
};

const authController = {
  // 1. refreshToken 검증
  async refreshToken(req, res) {
    const { refreshToken } = req.body;
    if (!refreshToken) {
      return res.sendError(401, "리프레시 토큰이 제공되지 않았습니다.");
    }

    try {
      const decoded = await jwt.refreshVerify(refreshToken);
      if (decoded) {
        const refreshToken = await getRedisData(`refreshToken:${decoded.userId}`);
        if (refreshToken) {
          const newAccessToken = jwt.sign({ id: decoded.userId });
          // 2. refresh token이 유효하면 새로운 access token 발급
          return res.sendSuccess("요청 성공", { newAccessToken });
        } else {
          return res.sendError(403, "유효하지 않은 리프레시 토큰입니다.");
        }
      } else {
        return res.sendError(403, "유효하지 않은 리프레시 토큰입니다.");
      }
    } catch (error) {
      return res.sendError();
    }
  },
  async requestEmail(req, res) {
    const { email } = req.body;
    if (!email) return res.sendError(400, "이메일이 필요합니다.");
    try {
      // 이메일 중복 확인
      let existingUser = await userModel.findByEmail(email);
      if (existingUser) {
        return res.sendError(400, "중복된 이메일 입니다.");
      }
      const authCode = Math.floor(100000 + Math.random() * 900000).toString();

      redisClient.set(`emailAuthCode:${email}`, authCode, "EX", 60 * 3);

      const mailOptions = {
        to: email, // 받는 사람
        subject: "moimmoim 인증번호 입니다.", // 메일 제목
        html: `<h1>안녕하세요</h1><p>moimmoim인증번호는 :${authCode} 입니다</p>`, // HTML 형식으로 작성 가능
      };
      const emailInfo = await mailSand(mailOptions);
      res.sendSuccess(`Email sent successfully! Response: ${emailInfo}`);
    } catch (error) {
      console.log("error", error);
      res.sendError();
    }
  },
  async confirmEmail(req, res) {
    const { email, code } = req.body;
    if (!email || !code) return res.status(400).json({ message: "필수값 확인하세요." });
    try {
      const storedCode = await getEmailAuthCode(email);
      console.log("storedCode", storedCode);
      if (storedCode === code) {
        // 인증 성공
        await redisClient.del(`emailAuthCode:${email}`); // 인증 후 코드를 삭제

        res.sendSuccess("인증 성공");
      } else {
        res.sendError(201, "인증 실패");
      }
    } catch (error) {
      console.log("error", error);
      res.sendError();
    }
  },
  //회원 가입
  async register(req, res) {
    try {
      const { email, password, passwordCheck, nickname, birthdate, provider, interests, addresses } = req.body;
      // interests 배열 및 addresses 배열 파싱
      // const interests = req.body.interests.map(Number);
      // const addresses = req.body.addresses.map((address) => ({
      //   address: address.address,
      //   address_code: address.address_code,
      // }));
      const ip = req.ip || req.connection.remoteAddress;
      // 이메일 중복 확인
      let existingUser = await userModel.findByEmail(email);
      if (existingUser) {
        return res.sendError(400, "중복된 이메일 입니다.");
      }
      existingUser = await userModel.findByNickname(nickname);
      if (existingUser) {
        return res.sendError(400, "중복된 닉네임 입니다.");
      }
      if (password !== passwordCheck) {
        return res.sendError(400, "패스워드 일치하지 않습니다.");
      }
      const gender = getGender(birthdate);

      if (!gender) {
        return res.sendError(400, "주민등록번호 잘못입력하셨습니다.");
      }
      // 비밀번호 해시 처리
      const hashedPassword = await bcrypt.hash(password, 10);

      // let profileImageName = null;
      // if (req.file) {
      //   // 유틸리티 함수를 호출하여 Azure에 업로드
      //   const { blobName } = await azureUtil.uploadFile(
      //     "profile",
      //     req.file.buffer,
      //     req.file.originalname
      //   );
      //   profileImageName = blobName;
      // }
      // console.log("profileImageName", profileImageName);

      // 새로운 사용자 생성
      const userId = await userModel.createUser({
        email,
        hashedPassword,
        nickname,
        birthdate,
        gender,
        provider,
        ip,
      });
      const resultInterest = await Promise.all(interests.map((item) => userModel.createUserInterest({ user_id: userId, interest_id: item })));
      const resultAddress = await Promise.all(
        // 지역코드 (RC0001~999) 있는지 없는지 체크후 있으면 등록 없으면 +1해서 등록.
        addresses.map(async (item) => {
          // let rcCode = "RC001"; // 기본값
          let findAddressRes = await addressModel.findAddress({
            address: item.address,
          });
          console.log("rcCode111", findAddressRes?.address_code, findAddressRes);
          if (!findAddressRes?.address_code) {
            // 가장 높은 address_code 가져오기
            const highestCode = await userModel.getHighestAddressCode();
            const newCodeNumber = highestCode ? parseInt(highestCode.replace("RC", ""), 10) + 1 : 1; // 기본값 1
            console.log("highestCode", highestCode);
            console.log("newCodeNumber", newCodeNumber);
            rcCode = `RC${String(newCodeNumber).padStart(3, "0")}`; // "RC001" 형식 유지

            // 주소 생성
            const createAddressRes = await addressModel.createAddress({
              address: item.address,
              address_code: findAddressRes?.address_code || rcCode,
              region_1depth_name: item.region_1depth_name,
              region_2depth_name: item.region_2depth_name,
              region_3depth_name: item.region_3depth_name,
            });

            console.log("createAddressRescreateAddressRes", createAddressRes);

            // 유저 - 주소 추가
            return userModel.createUserAddress({
              user_id: userId,
              address_id: createAddressRes,
            });
          } else {
            return userModel.createUserAddress({
              user_id: userId,
              address_id: findAddressRes.id,
            });
          }
        })
      );

      res.sendSuccess("회원가입 완료", { userId });
    } catch (error) {
      console.log("error", error);
      res.sendError();
    }
  },

  async confirmNickname(req, res) {
    const { nickname } = req.query;
    try {
      const existingUser = await userModel.findByNickname(nickname);
      if (existingUser) {
        return res.sendError(400, "중복된 닉네임 입니다.");
      }
      res.sendSuccess("닉네임 사용가능");
    } catch (error) {
      console.log("error", error);
      res.sendError();
    }
  },

  // moimmoim 회원로그인
  async login(req, res) {
    const { email, password, fcmToken } = req.body;

    console.log();

    try {
      // 1. 사용자가 존재하는지 이메일로 찾기
      const user = await userModel.findByEmail(email);
      if (!user) {
        return res.sendError(401, "계정 정보가 틀렸습니다. 확인바랍니다.");
      }
      // 2. 비밀번호 확인
      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) {
        return res.sendError(401, "계정 정보가 틀렸습니다. 확인바랍니다.");
      }

      subscribeUserToTopic({ fcmToken, users_id: user.id });

      const accessToken = jwt.sign(user);
      const refreshToken = jwt.refresh(user);
      res.sendSuccess("로그인 되었습니다.", { accessToken, refreshToken });
    } catch (error) {
      console.log("error", error);
      res.sendError();
    }
  },

  // 소셜로그인 팝업.
  async socialUrl(req, res) {
    const provider = req.params.provider; // 'kakao', 'google', 'apple' 등 서비스 이름을 URL에서 받음
    try {
      const authUrl = getAuthUrl(provider); // 동적으로 로그인 URL 생성
      res.redirect(authUrl);
    } catch (error) {
      res.sendError();
    }
  },

  // 소셜로그인 팝업후 리다이렉트 url
  async socialLogin(req, res) {
    const ip = req.ip || req.connection.remoteAddress;
    const { code } = req.query;
    const provider = req.params.provider; // 'kakao', 'google', 'apple' 등 서비스 이름을 URL에서 받음
    console.log("provider", provider);
    try {
      // 각 서비스별 클라이언트 ID, 비밀, 토큰 URL 등 매핑 설정
      const config = getProviderConfig(provider);
      if (!config) {
        return res.sendError(400, "지원되지 않는 소셜 로그인 제공자입니다.");
      }

      // 1. 인가 코드로 액세스 토큰 요청
      const params = {
        grant_type: "authorization_code",
        client_id: config.client_id,
        client_secret: config.client_secret,
        redirect_uri: process.env[`${provider.toUpperCase()}_REDIRECT_URI`],
        code: code,
      };
      const tokenResponse = await axios.post(config.token_url, null, {
        params,
        headers: { "Content-type": "application/x-www-form-urlencoded" },
      });
      const accessToken = tokenResponse.data.access_token;

      // 2. 액세스 토큰으로 사용자 정보 요청
      const userResponse = await axios.get(config.user_info_url, {
        headers: { Authorization: `Bearer ${accessToken}` },
      });
      const userData = userResponse.data?.kakao_account;
      console.log("userData", userData);

      const email = userData.email || `${provider}_${userData.id}@${provider}.com`; // 이메일이 없으면 고유 ID로 설정
      let user = await userModel.findByEmail(email, provider);
      const birthdate = `${userData.birthyear.slice(2)}${userData.birthday}`;
      const nickname = userData.name;
      const gender = getResidentNumberFirstDigit(userData.birthyear, userData.gender);
      // 3. 기존 사용자가 없으면 회원가입 처리
      if (!user) {
        res.redirect(`${process.env.FRONTEND_URL}/sign?email=${email}&birthdate=${birthdate}&nickname=${nickname}&provider=${provider}&gender=${gender}`);
      } else {
        const accessToken = jwt.sign(user);
        const refreshToken = jwt.refresh(user);
        res.redirect(`${process.env.FRONTEND_URL}?accessToken=${accessToken}&refreshToken=${refreshToken}`);
      }
    } catch (error) {
      console.log("error", error);
      res.sendError(500, `${provider} 로그인 중 서버 에러가 발생했습니다.`);
    }
  },

  async getInterests(req, res) {
    try {
      const interestList = await categoryModel.getCategorysInterest();
      res.sendSuccess("성공", interestList);
    } catch (error) {
      res.sendError();
    }
  },
};

module.exports = authController;
