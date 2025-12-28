import express from 'express';
import { AuthRoutes } from '../app/modules/auth/auth.route';
import { UserRoutes } from '../app/modules/user/user.route';
// import { NotificationRoutes } from '../app/modules/notifications/notifications.route';
// import { settingRoutes } from '../app/modules/setting/setting.route';
// import { privacyRoutes } from '../app/modules/privacy/privacy.routes';
// import { aboutRoutes } from '../app/modules/aboutUs/aboutUs.route';
// import { tersmConditionRoutes } from '../app/modules/termsAndCondition/termsAndCondition.route';

const router = express.Router();

const apiRoutes = [
  { path: '/user', route: UserRoutes },
  { path: '/auth', route: AuthRoutes },

  // { path: '/notification', route: NotificationRoutes },
  // { path: '/setting', route: settingRoutes },
  // { path: '/privacy', route: privacyRoutes },
  // { path: '/about', route: aboutRoutes },
  // { path: '/terms', route: tersmConditionRoutes },

  // { path: '/payment', route: PaymentRoutes },
  // { path: '/package', route: packageRoute },
  // { path: '/subscription', route: SubscriptionRoutes },
];

apiRoutes.forEach(route => router.use(route.path, route.route));

export default router;
